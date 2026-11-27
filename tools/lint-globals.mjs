/*
 * Regenerate the oxlint `globals` block in .oxlintrc.json.
 *
 * The payload runs inside GameFace, where the CivSwitch loader exposes every core
 * binding as a bare global. Without the list, `no-undef` reports all of them, which
 * is why it used to be disabled; with it, `no-undef` turns into a typo detector for
 * the names the core really provides.
 *
 * The list derives from tools/bundle.mjs, so adding a core function only needs a
 * regeneration. A separate config file is not an option: oxlint 1.95 merges the
 * rules of `extends` but silently drops the `globals` of the extended file.
 *
 * Pass --check to fail on a stale block instead of rewriting it.
 */

import fs from "node:fs";
import path from "node:path";
import {fileURLToPath} from "node:url";
import {CORE_GLOBALS, coreBindingNames} from "./bundle.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const CONFIG_PATH = path.join(ROOT, ".oxlintrc.json");
const GLOBALS_ANCHOR = "\"globals\": {";
const ENTRY_INDENT = " ".repeat(8);
const CLOSING_INDENT = " ".repeat(4);

// Loader and GameFace provide these globals; no core file declares them.
const NATIVE_GLOBALS = ["Network", "Sound", "free", "gc", "malloc", "sdk_base"];

function main() {
    const source = fs.readFileSync(CONFIG_PATH, "utf8");
    const expected = replaceGlobalsBlock(source, collectGlobals());

    if (process.argv.includes("--check")) {
        assertCurrent(source, expected);
        return;
    }

    if (expected === source) {
        console.log(".oxlintrc.json globals already current");
        return;
    }

    fs.writeFileSync(CONFIG_PATH, expected);
    console.log(`wrote .oxlintrc.json globals (${Object.keys(collectGlobals()).length} names)`);
}

function collectGlobals() {
    const names = new Set([...coreBindingNames(), ...CORE_GLOBALS, ...NATIVE_GLOBALS]);
    const globals = {};

    for (const name of [...names].sort()) {

        /*
         * Writable rather than readonly: a few core files assign their own top-level
         * binding later, and `readonly` would report that as a global assignment.
         */
        globals[name] = "writable";
    }

    return globals;
}

function replaceGlobalsBlock(source, globals) {
    const anchorIndex = source.indexOf(GLOBALS_ANCHOR);

    if (anchorIndex === -1) {
        throw new Error("no \"globals\" block in .oxlintrc.json to regenerate");
    }

    const openIndex = anchorIndex + GLOBALS_ANCHOR.length - 1;
    const closeIndex = findClosingBrace(source, openIndex);
    const entries = Object.keys(globals)
        .map(name => `${ENTRY_INDENT}${JSON.stringify(name)}: "writable"`)
        .join(",\n");
    const block = `{\n${entries}\n${CLOSING_INDENT}}`;

    return source.slice(0, openIndex) + block + source.slice(closeIndex + 1);
}

function findClosingBrace(source, openIndex) {
    let depth = 0;
    let inString = false;

    for (let index = openIndex; index < source.length; index++) {
        const character = source[index];
        const isEscape = inString && character === "\\";
        const isQuote = character === "\"";

        if (isEscape) {
            // Skip the character the backslash protects, quote included.
            index++;
            continue;
        }

        if (isQuote) {
            inString = !inString;
            continue;
        }

        if (character === "{") {
            depth++;
        }

        if (character === "}") {
            depth--;

            if (depth === 0) {
                return index;
            }
        }
    }

    throw new Error("unbalanced braces in .oxlintrc.json");
}

function assertCurrent(source, expected) {
    if (source === expected) {
        return;
    }

    throw new Error(".oxlintrc.json globals are stale; run npm run lint:globals");
}

main();
