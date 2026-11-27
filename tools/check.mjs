/*
 * Syntax-check every source file, then verify the size of the bundled payload.
 *
 * Layout is only checked in the files we own: the vendored persist/ tree keeps its
 * upstream formatting.
 */

import * as acorn from "acorn";
import {spawnSync} from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import {
    buildPayload,
    CORE_DIR,
    CORE_FILES,
    CORE_GLOBALS,
    coreBindingNames,
    MAX_PAYLOAD_BYTES,
    ROOT,
    SRC_DIR
} from "./bundle.mjs";

const PREFERRED_LINE_COLUMNS = 140;
const SPLIT_STRING = /["']\s*\+\s*$/;
const QUOTED_START = /^["']/;

function walk(directory) {
    const files = [];
    for (const entry of fs.readdirSync(directory, {withFileTypes: true})) {
        const fullPath = path.join(directory, entry.name);

        if (entry.isDirectory()) {
            files.push(...walk(fullPath));
        } else if (entry.isFile() &&
            (entry.name.endsWith(".js") || entry.name.endsWith(".mjs"))) {
            files.push(fullPath);
        }
    }
    return files;
}

for (const file of CORE_FILES) {
    const fullPath = path.join(CORE_DIR, file);

    if (!fs.existsSync(fullPath)) {
        throw new Error(`missing core file: ${path.relative(SRC_DIR, fullPath)}`);
    }
}

/*
 * Every coreRuntime property a payload module uses has to exist in the injected
 * core. That way a removed core helper fails here instead of on the console.
 */
const availableBindings = new Set([...coreBindingNames(), ...CORE_GLOBALS]);
const payloadFiles = [
    path.join(SRC_DIR, "core.js"),
    path.join(SRC_DIR, "core", "steps", "setup.mjs"),
    path.join(SRC_DIR, "core", "steps", "canary.mjs"),
    path.join(SRC_DIR, "core", "steps", "alias.mjs"),
    path.join(SRC_DIR, "core", "steps", "discovery.mjs"),
    path.join(SRC_DIR, "core", "steps", "cleanup.mjs"),
    path.join(SRC_DIR, "core", "ipc", "entry-type.mjs"),
    path.join(SRC_DIR, "core", "helpers", "index.mjs"),
    path.join(SRC_DIR, "core", "helpers", "util.mjs"),
    path.join(SRC_DIR, "core", "helpers", "scan.mjs"),
    path.join(SRC_DIR, "core", "helpers", "metadata-discovery.mjs"),
    path.join(SRC_DIR, "core", "helpers", "cache.mjs"),
    path.join(SRC_DIR, "core", "helpers", "wave.mjs"),
    path.join(SRC_DIR, "core", "steps", "promotion.mjs"),
    path.join(SRC_DIR, "core", "logger.mjs")
];
const usedBindings = new Set();
for (const file of payloadFiles) {
    const source = fs.readFileSync(file, "utf8");
    for (const match of source.matchAll(/coreRuntime\.([A-Za-z_$][\w$]*)/g)) {
        usedBindings.add(match[1]);
    }
    for (const match of source.matchAll(/const\s*\{([\s\S]*?)\}\s*=\s*coreRuntime\s*;/g)) {
        for (const name of match[1].split(",")) {
            const trimmed = name.trim();

            if (/^[A-Za-z_$][\w$]*$/.test(trimmed)) {
                usedBindings.add(trimmed);
            }
        }
    }
}
const missingBindings = [...usedBindings]
    .filter(name => !availableBindings.has(name))
    .sort();

if (missingBindings.length) {
    throw new Error("payload uses missing core bindings: " +
        missingBindings.join(", "));
}

// Flag adjacent strings that would fit together on one line.
function assertStyle(files) {
    const offenders = [];
    for (const file of files) {
        const lines = fs.readFileSync(file, "utf8").split("\n");
        for (let index = 0; index < lines.length; index++) {
            const line = lines[index];
            const where = path.relative(ROOT, file) + ":" + (index + 1);

            if (index + 1 < lines.length && SPLIT_STRING.test(line)) {
                const nextLine = lines[index + 1].trim();
                const joined = line.trimEnd() + " " + nextLine;
                const carriesNewline = line.includes("\\n") ||
                    nextLine.includes("\\n");

                if (QUOTED_START.test(nextLine) && !carriesNewline &&
                    joined.length <= PREFERRED_LINE_COLUMNS) {
                    offenders.push(where + " (split string fits on one line)");
                }
            }
        }
    }

    if (offenders.length) {
        throw new Error("style violations: " + offenders.join(", "));
    }
}

function controlBlocks(node) {
    if (node.type === "IfStatement") {
        return [node.consequent, node.alternate];
    }

    switch (node.type) {
        case "ForStatement":
        case "ForInStatement":
        case "ForOfStatement":
        case "WhileStatement":
        case "DoWhileStatement":
            return [node.body];
        case "TryStatement":
            return [node.block, node.handler?.body, node.finalizer];
        default:
            return [];
    }
}

function assertConditionalLayout(files) {
    const offenders = [];

    for (const file of files) {
        const source = fs.readFileSync(file, "utf8");
        const relativePath = path.relative(ROOT, file);
        const sourceType = file.endsWith(".mjs") ||
            relativePath === "src/core.js" ||
            relativePath.startsWith("tools/") ||
            relativePath.startsWith("examples/")
            ? "module" : "script";
        const ast = acorn.parse(source, {
            ecmaVersion: "latest",
            sourceType,
            locations: true
        });
        const lines = source.split(/\r?\n/);

        function hasBlankLineBetween(firstLine, secondLine) {
            for (let line = firstLine + 1; line < secondLine; line++) {
                if (lines[line - 1].trim() === "") {
                    return true;
                }
            }
            return false;
        }

        function isBlockConditional(statement) {
            return statement.type === "IfStatement" &&
                (statement.consequent.type === "BlockStatement" ||
                statement.alternate?.type === "BlockStatement" ||
                statement.alternate?.type === "IfStatement");
        }

        function visit(node) {
            if (!node || typeof node !== "object") {
                return;
            }

            if (Array.isArray(node)) {
                for (const child of node) {
                    visit(child);
                }
                return;
            }

            for (const block of controlBlocks(node)) {
                if (!block || block.type !== "BlockStatement" ||
                    block.body.length === 0) {
                    continue;
                }

                const firstStatement = block.body[0];
                const lastStatement = block.body[block.body.length - 1];

                if (firstStatement.loc.start.line === block.loc.start.line) {
                    offenders.push(relativePath + ":" + block.loc.start.line +
                        " (block body shares its control line)");
                } else if (lastStatement.loc.end.line === block.loc.end.line) {
                    offenders.push(relativePath + ":" + block.loc.end.line +
                        " (closing brace shares a line with its body)");
                }
            }

            let bodyKey = null;

            if (node.type === "Program" || node.type === "BlockStatement") {
                bodyKey = "body";
            } else if (node.type === "SwitchCase") {
                bodyKey = "consequent";
            }

            if (bodyKey) {
                const body = node[bodyKey];

                for (let index = 0; index + 1 < body.length; index++) {
                    const previous = body[index];
                    const current = body[index + 1];

                    if (!isBlockConditional(previous) &&
                        !isBlockConditional(current)) {
                        continue;
                    }

                    if (!hasBlankLineBetween(previous.loc.end.line, current.loc.start.line)) {
                        offenders.push(relativePath + ":" +
                            current.loc.start.line +
                            " (missing blank line around if/else block)");
                    }
                }

                for (const statement of body) {
                    visit(statement);
                }
            }

            for (const [key, value] of Object.entries(node)) {
                if (["loc", "start", "end", bodyKey].includes(key)) {
                    continue;
                }

                visit(value);
            }
        }

        visit(ast);
    }

    if (offenders.length) {
        throw new Error("conditional layout violations: " +
            offenders.join(", "));
    }
}

/*
 * Two closed vocabularies reach the label tables in log-format.mjs: the gate keys
 * checkWindow() can reject on, and the role names the worker plans use. Three
 * mistakes stay silent at runtime, which is why both directions get checked here: a
 * gate with no label, a label for a gate that no longer exists, and a role missing
 * its name.
 */
function walkAst(node, visit) {
    if (!node || typeof node !== "object") {
        return;
    }

    if (Array.isArray(node)) {
        for (const child of node) {
            walkAst(child, visit);
        }

        return;
    }

    if (typeof node.type === "string") {
        visit(node);
    }

    for (const [key, value] of Object.entries(node)) {
        if (!["loc", "start", "end"].includes(key)) {
            walkAst(value, visit);
        }
    }
}

function parseModule(relativePath) {
    const source = fs.readFileSync(path.join(ROOT, relativePath), "utf8");
    return acorn.parse(source, {ecmaVersion: "latest", sourceType: "module"});
}

function declaredInit(ast, name) {
    let init = null;
    walkAst(ast, node => {
        if (node.type === "VariableDeclarator" && node.id?.name === name) {
            init = node.init;
        }
    });
    return init;
}

function objectKeyNames(node) {
    return (node?.properties || []).map(property => {
        if (property.key.type === "Identifier") {
            return property.key.name;
        }

        return property.key.value;
    });
}

function stringElements(node) {
    return (node?.elements || []).map(element => element.value);
}

function setMembers(ast, name) {
    return stringElements(declaredInit(ast, name)?.arguments?.[0]);
}

function checkWindowGateKeys(ast) {
    let keys = [];
    walkAst(ast, node => {
        if (node.type === "CallExpression" && node.callee?.name === "checkWindow" &&
            node.arguments.length > 0) {
            keys = objectKeyNames(node.arguments[0]);
        }
    });
    return keys;
}

function coverageProblems(vocabulary, known, vocabularyName) {
    const problems = [];

    if (vocabulary.length === 0) {
        problems.push(`could not read the ${vocabularyName} vocabulary`);
        return problems;
    }

    for (const key of vocabulary) {
        if (!known.includes(key)) {
            problems.push(`no label for "${key}"`);
        }
    }

    for (const key of known) {
        if (!vocabulary.includes(key)) {
            problems.push(`label for unknown "${key}"`);
        }
    }

    return problems;
}

function assertVocabularyCoverage() {
    const format = parseModule("src/core/log-format.mjs");
    const wave = parseModule("src/core/helpers/wave.mjs");
    const config = parseModule("src/core/config.mjs");
    const gateKeys = checkWindowGateKeys(wave);
    const labels = [
        ...objectKeyNames(declaredInit(format, "GATE_LABELS")),
        ...setMembers(format, "GATE_SPECIALIZED"),
        ...setMembers(format, "GATE_DEDICATED")
    ];
    const roleNames = objectKeyNames(declaredInit(format, "ROLE_NAMES"));
    const roles = stringElements(declaredInit(config, "roleLabels"));
    const problems = [
        ...coverageProblems(gateKeys, labels, "gate"),
        ...coverageProblems(roles, roleNames, "role")
    ];

    if (problems.length) {
        throw new Error("vocabulary coverage violations: " + problems.join(", "));
    }
}

// Layout checks cover owned files; persist/ is vendored and syntax-checked only.
const ownedFiles = [
    ...walk(SRC_DIR),
    ...walk(path.join(ROOT, "tools")),
    ...walk(path.join(ROOT, "examples"))
];
const sourceFiles = [
    ...ownedFiles,
    ...walk(path.join(ROOT, "persist"))
];
for (const file of sourceFiles) {
    const result = spawnSync(process.execPath, ["--check", file], {
        encoding: "utf8"
    });

    if (result.status !== 0) {
        process.stderr.write(result.stderr || result.stdout || "");
        throw new Error(`syntax check failed: ${path.relative(process.cwd(), file)}`);
    }
}

const built = await buildPayload();

if (built.bytes > MAX_PAYLOAD_BYTES) {
    throw new Error(`payload is too large: ${built.bytes} bytes`);
}

assertStyle(ownedFiles);
assertConditionalLayout(ownedFiles);
assertVocabularyCoverage();

console.log(`OK: ${sourceFiles.length} source files; payload ${built.bytes} bytes` +
    (built.identifiersMinified ? " (ESM identifiers minified)" : "") +
    (built.minified ? " (full bundle minification for loader limit)" : "")
);
