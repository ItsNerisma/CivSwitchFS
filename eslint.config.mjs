import stylistic from "@stylistic/eslint-plugin";

// Keep authored row breaks and trailing comments in multiline argument lists.
const firstArgumentInline = {
    meta: {type: "layout", schema: [], fixable: "whitespace", messages: {inline: "Keep the first argument or parameter beside the opening parenthesis."}},
    create(context) {
        const source = context.sourceCode;

        function check(open) {
            const next = source.getTokenAfter(open, {includeComments: true});

            if (next.type === "Line" || next.type === "Block" || open.loc.end.line === next.loc.start.line) {
                return;
            }

            context.report({node: next, messageId: "inline", fix: fixer => fixer.removeRange([open.range[1], next.range[0]])});
        }

        return {
            CallExpression(node) {
                if (node.arguments.length) {
                    check(source.getTokenAfter(node.callee, token => token.value === "("));
                }
            },
            "FunctionDeclaration, FunctionExpression"(node) {
                if (node.params.length) {
                    check(source.getFirstToken(node, token => token.value === "("));
                }
            }
        };
    }
};

export default [
    {
        ignores: ["**/.*", "dist/**", "llm/**", "logs/**", "persist/**", "test-payloads/**"]
    },
    {
        files: ["{src,tools,examples}/**/*.{js,mjs}", "eslint.config.mjs"],
        plugins: {"@stylistic": stylistic, local: {rules: {"first-argument-inline": firstArgumentInline}}},
        rules: {
            curly: ["error", "all"],
            "@stylistic/brace-style": ["error", "1tbs", {allowSingleLine: false}],
            "local/first-argument-inline": "error",
            "@stylistic/indent": ["error", 4, {
                SwitchCase: 1,
                CallExpression: {arguments: "first"},
                FunctionDeclaration: {parameters: "first"},
                FunctionExpression: {parameters: "first"}
            }],
            "@stylistic/no-trailing-spaces": "error",
            "@stylistic/padding-line-between-statements": ["error",
                {blankLine: "always", prev: "*", next: "if"},
                {blankLine: "always", prev: "if", next: "*"}
            ],
            "@stylistic/quotes": ["error", "double", {allowTemplateLiterals: "always"}],
            "@stylistic/semi": ["error", "always"]
        }
    },
    {
        files: ["src/core/**/*.js"],
        languageOptions: {sourceType: "script"}
    }
];
