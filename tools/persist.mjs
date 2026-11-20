#!/usr/bin/env node
/** Build and install the CivSwitchFS image into the Civ VII trigger save. */

import {createHash, randomUUID} from "node:crypto";
import {readFile} from "node:fs/promises";
import net from "node:net";
import path from "node:path";
import {fileURLToPath} from "node:url";
import {buildPersistentImage} from "./persist-build.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const BOOTSTRAP = path.join(ROOT, "dist/persist/persist-bootstrap.js");
const TEMPLATE = path.join(ROOT, "dist/persist/save-template.bin");
const TEMPLATE_SHA256 =
    "32fa8a0d6dd0a480d8e541e63ea44c4619bc6f7be4282cfc3cb6a4f6d305dfae";
const CHUNK_BYTES = 400_000;
const MAX_LOADER_BYTES = 500_000;

function sha256(bytes) {
    return createHash("sha256").update(bytes).digest("hex");
}

function sendAndWait(host, port, code, timeoutMs = 60_000) {
    let payload;
    if (Buffer.isBuffer(code)) {
        payload = code;
    } else {
        payload = Buffer.from(code, "ascii");
    }
    if (!payload.length || payload.length >= MAX_LOADER_BYTES)
        return Promise.reject(
            new Error("Payload is empty or exceeds 500,000 bytes"));
    return new Promise((resolve, reject) => {
        const chunks = [];
        let settled = false;
        const socket = net.createConnection({host, port});
        const timeout = setTimeout(() => {
            finish(new Error("The loader did not finish the payload in time"));
            socket.destroy();
        }, timeoutMs);
        function finish(error, value) {
            if (settled) return;
            settled = true;
            clearTimeout(timeout);
            if (error) reject(error);
            else resolve(value);
        }
        socket.once("connect", () => socket.end(payload));
        // Show logs when available, without requiring a loader relay.
        socket.on("data", chunk => chunks.push(chunk));
        socket.once("end", () => finish(
            null, Buffer.concat(chunks).toString("utf8")));
        socket.once("error", error => finish(error));
        socket.once("close", hadError => {
            if (settled) return;
            if (hadError) {
                finish(new Error("Connection to the loader was interrupted"));
                return;
            }
            finish(new Error("The loader closed before the command completed"));
        });
    });
}

async function runPayload(host, port, body, cleanup = false) {
    let dispose = "";
    if (cleanup) {
        dispose = "finally{" +
            "window.__cfsPersistInstaller.dispose();" +
            "delete window.__cfsPersistInstaller;}";
    }
    const code = "(async function(){try{" + body + "}" +
        "catch(error){await log('Installation failed: '+String(" +
        "error && error.message ? error.message : error));" +
        "await log(String(error && error.stack ? error.stack : '')" +
        ".slice(0, 400));}" +
        dispose + "})()";
    const output = await sendAndWait(host, port, code, 300_000);
    if (output) {
        process.stdout.write(output);
        if (!output.endsWith("\n")) process.stdout.write("\n");
    }
    const failureLine = output.split(/\r?\n/).find(line =>
        line.startsWith("Installation failed: ") ||
        line.startsWith("Error in payload: ")
    );
    if (failureLine) throw new Error(failureLine);
    return output;
}

async function install(host, port, bootstrapPath, templatePath) {
    const [bootstrap, template] = await Promise.all([
        readFile(bootstrapPath),
        readFile(templatePath)
    ]);
    if (!bootstrap.length || bootstrap.length >= MAX_LOADER_BYTES ||
        bootstrap.some(byte => byte > 0x7f))
        throw new Error("Invalid bootstrap; rerun npm run persist");
    if (sha256(template) !== TEMPLATE_SHA256)
        throw new Error("Civ VII template fingerprint mismatch");

    const base64 = template.toString("base64");
    const token = randomUUID().replaceAll("-", "");
    console.log("Preparing persistent image...");

    const bootstrapOutput = await runPayload(
        host,
        port,
        'await log("Bootstrap eval started.");' +
            bootstrap.toString("ascii") +
            '\nawait log("Installer ready.");'
    );
    if (!bootstrapOutput) console.log("Installer bootstrap sent.");

    const count = Math.ceil(base64.length / CHUNK_BYTES);
    for (
        let offset = 0, index = 1;
        offset < base64.length;
        offset += CHUNK_BYTES, index++
    ) {
        const part = base64.slice(offset, offset + CHUNK_BYTES);
        const marker = `Template ${index}/${count} received.`;
        const body = "await window.__cfsPersistInstaller.stageChunk(" +
            JSON.stringify(token) + "," + index + "," + offset + "," +
            JSON.stringify(part) + ");await log(" +
            JSON.stringify(marker) + ");";
        const output = await runPayload(host, port, body);
        if (!output) console.log(`Template ${index}/${count} sent.`);
    }

    const installed = "Installed. Restart the game, then Load a game.";
    const finalOutput = await runPayload(
        host,
        port,
        "await window.__cfsPersistInstaller.installFromTemplate();" +
            "await log(" + JSON.stringify(installed) + ");",
        true
    );
    if (!finalOutput.split(/\r?\n/).includes(installed)) {
        console.log(
            "No completion log reached the PC. Wait for " +
            `"${installed}" on the Switch before restarting.`
        );
    }
}

function parseArgs(args) {
    const positional = [];
    const options = {
        port: 9026,
        bootstrap: BOOTSTRAP,
        template: TEMPLATE,
        rebuild: true,
        debugPayload: false,
        minifyPayload: false,
        payloadModeSpecified: false
    };
    for (let index = 0; index < args.length; index++) {
        const arg = args[index];
        if (arg === "--no-build") {
            options.rebuild = false;
            continue;
        }
        if (arg === "--debug-payload") {
            options.debugPayload = true;
            options.payloadModeSpecified = true;
            continue;
        }
        if (arg === "--minify-payload") {
            options.minifyPayload = true;
            options.payloadModeSpecified = true;
            continue;
        }
        if (arg === "--port" || arg === "--bootstrap" || arg === "--template") {
            const value = args[++index];
            if (!value) throw new Error(`Missing value for ${arg}`);
            const key = arg.slice(2);
            if (key === "port") {
                options[key] = Number(value);
            } else {
                options[key] = path.resolve(value);
            }
        } else if (arg.startsWith("--")) {
            throw new Error(`Unknown option: ${arg}`);
        } else positional.push(arg);
    }
    if (positional.length !== 1) {
        throw new Error("Usage: npm run persist -- <SWITCH_IP> " +
            "[--port 9026] [--no-build] [--minify-payload | --debug-payload] " +
            "[--bootstrap path] [--template path]");
    }
    if (!Number.isInteger(options.port) || options.port < 1 ||
        options.port > 65535)
        throw new Error("Invalid port");
    if (options.debugPayload && options.minifyPayload)
        throw new Error("Choose either --debug-payload or --minify-payload");
    if (options.payloadModeSpecified && !options.rebuild)
        throw new Error(
            "Payload mode options require a rebuild; remove --no-build");
    return {host: positional[0], ...options};
}

if (process.argv[1] &&
    path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    try {
        const options = parseArgs(process.argv.slice(2));
        if (options.rebuild) {
            console.log("Building persistent image...");
            await buildPersistentImage({
                debugPayload: options.debugPayload,
                minifyPayload: options.minifyPayload
            });
        }
        await install(
            options.host,
            options.port,
            options.bootstrap,
            options.template
        );
    } catch (error) {
        console.error("Persistence failed: " + error.message);
        process.exitCode = 1;
    }
}
