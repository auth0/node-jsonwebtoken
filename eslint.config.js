import globals from 'globals'

import js from '@eslint/js'

import ts from '@typescript-eslint/eslint-plugin'
import parser from '@typescript-eslint/parser'

import prettier from 'eslint-plugin-prettier'

import jest from 'eslint-plugin-jest'

/** @type{import('eslint').Linter.Config[]} */
const config = [
  js.configs.recommended,
  { ignores: ['node_modules', 'coverage', 'dist'] },
  {
    plugins: {
      '@typescript-eslint': ts
    },
    languageOptions: {
      parser,
      parserOptions: {
        ecmaVersion: 'latest',
        sourceType: 'module'
      },
      globals: {
        ...globals.node,
        ...globals.es2022
      }
    },
    rules: {
      ...ts.configs.recommended.rules
    }
  },
  {
    plugins: {
      prettier
    },
    rules: {
      ...prettier.configs.recommended.rules
    }
  },
  {
    files: ['**/*.spec.ts', '**/*.test.ts'],
    plugins: {
      jest
    },
    languageOptions: {
      globals: {
        ...globals.jest
      }
    },
    rules: {
      ...jest.configs.recommended.rules
    }
  }
]

export default config
