module.exports = [
  {
    ignores: ["node_modules/**", "coverage/**", "dist/**", ".nyc_output/**", "convert-tests-to-async.js"]
  },
  {
    files: ["**/*.js"],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: "script",
      globals: {
        Buffer: "readonly",
        process: "readonly",
        console: "readonly",
        require: "readonly",
        module: "readonly",
        exports: "readonly",
        __dirname: "readonly",
        __filename: "readonly"
      }
    },
    rules: {
      "comma-style": "error",
      "dot-notation": "error",
      "indent": ["error", 2],
      "no-control-regex": "error",
      "no-div-regex": "error",
      "no-eval": "error",
      "no-implied-eval": "error",
      "no-invalid-regexp": "error",
      "no-trailing-spaces": "error",
      "no-undef": "error",
      "no-unused-vars": "error",
      "prefer-const": "error",
      "prefer-arrow-callback": "warn",
      "prefer-destructuring": ["warn", {
        "object": true,
        "array": false
      }],
      "prefer-template": "warn",
      "no-var": "error",
      "arrow-body-style": ["warn", "as-needed"],
      "object-shorthand": ["warn", "always"]
    }
  },
  {
    files: ["test/compatibility-esm.test.js"],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: "module",
      globals: {
        Buffer: "readonly",
        process: "readonly",
        console: "readonly"
      }
    }
  },
  {
    files: ["test/**/*.js"],
    languageOptions: {
      globals: {
        describe: "readonly",
        it: "readonly",
        before: "readonly",
        beforeEach: "readonly",
        after: "readonly",
        afterEach: "readonly",
        context: "readonly",
        setTimeout: "readonly",
        expect: "readonly",
        jest: "readonly"
      }
    }
  }
];