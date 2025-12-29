const tsPlugin = require("@typescript-eslint/eslint-plugin");
const prettierConfig = require("eslint-config-prettier");

module.exports = [
  {
    ignores: ["dist/**", "node_modules/**", "coverage/**", ".vscode/**", ".DS_Store"],
  },
  {
    files: ["**/*.ts"],
    languageOptions: {
      parser: require("@typescript-eslint/parser"),
      parserOptions: {
        ecmaVersion: 2020,
        sourceType: "module",
        project: ["./tsconfig.build.json"],
      },
    },

    plugins: { "@typescript-eslint": tsPlugin },
    rules: Object.assign(
      {},
      tsPlugin.configs.recommended.rules,
      tsPlugin.configs["recommended-requiring-type-checking"].rules,
      prettierConfig.rules || {},
      {
        "@typescript-eslint/explicit-function-return-type": "off",
        "@typescript-eslint/explicit-module-boundary-types": "off",
        "@typescript-eslint/no-explicit-any": "off",
        "@typescript-eslint/no-unsafe-member-access": "off",
        "@typescript-eslint/no-unsafe-call": "off",
        "@typescript-eslint/no-unsafe-assignment": "off",
        "@typescript-eslint/no-unsafe-argument": "off",
        "@typescript-eslint/no-unsafe-return": "off",
        "@typescript-eslint/no-unused-expressions": "off",
        "no-console": ["warn", { allow: ["warn", "error", "debug", "log"] }],
      }
    ),
  },
];
