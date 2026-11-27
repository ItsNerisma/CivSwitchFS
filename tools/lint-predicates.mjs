/*
 * Warn when an if test combines more atomic predicates than the style limit allows.
 *
 * The warning is advisory: the existing exploit path still carries legacy instances.
 */

import fs from "node:fs";
import path from "node:path";
import {fileURLToPath} from "node:url";
import * as acorn from "acorn";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const MAX_IF_PREDICATES = 4;
const SOURCE_DIRECTORIES = ["src", "tools", "examples"];

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

function countAtomicPredicates(expression) {
    if (expression.type === "LogicalExpression" &&
        (expression.operator === "&&" || expression.operator === "||")) {
        return countAtomicPredicates(expression.left) +
            countAtomicPredicates(expression.right);
    }

    if (expression.type === "UnaryExpression" &&
        expression.operator === "!") {
        return countAtomicPredicates(expression.argument);
    }

    if (expression.type === "ConditionalExpression") {
        return countAtomicPredicates(expression.test) +
            countAtomicPredicates(expression.consequent) +
            countAtomicPredicates(expression.alternate);
    }

    if (expression.type === "ChainExpression") {
        return countAtomicPredicates(expression.expression);
    }

    return 1;
}

function parseFile(filePath, source) {
    const relativePath = path.relative(ROOT, filePath);
    const isModule = filePath.endsWith(".mjs") ||
        relativePath === "src/core.js";
    return acorn.parse(source, {
        ecmaVersion: "latest",
        sourceType: isModule ? "module" : "script",
        locations: true
    });
}

function visit(node, filePath, reports) {
    if (!node || typeof node !== "object") {
        return;
    }

    if (Array.isArray(node)) {
        for (const child of node) {
            visit(child, filePath, reports);
        }
        return;
    }

    if (node.type === "IfStatement") {
        const count = countAtomicPredicates(node.test);

        if (count > MAX_IF_PREDICATES) {
            reports.push({
                file: path.relative(ROOT, filePath),
                line: node.loc.start.line,
                column: node.loc.start.column + 1,
                count
            });
        }
    }

    for (const [key, value] of Object.entries(node)) {
        if (key === "loc" || key === "start" || key === "end") {
            continue;
        }

        visit(value, filePath, reports);
    }
}

const sourceFiles = SOURCE_DIRECTORIES.flatMap(directory =>
    walk(path.join(ROOT, directory)));
const reports = [];
for (const filePath of sourceFiles) {
    const source = fs.readFileSync(filePath, "utf8");
    const ast = parseFile(filePath, source);
    visit(ast, filePath, reports);
}

reports.sort((left, right) =>
    left.file.localeCompare(right.file) || left.line - right.line);
for (const report of reports) {
    console.warn(`${report.file}:${report.line}:${report.column}: warning ` +
        `if test has ${report.count} atomic predicates ` +
        `(limit ${MAX_IF_PREDICATES}); extract a named boolean helper ` +
        `without changing predicate order`);
}

console.log(`Predicate style check: ${reports.length} warning(s); ` +
    `limit is ${MAX_IF_PREDICATES} atomic predicates per if`);
