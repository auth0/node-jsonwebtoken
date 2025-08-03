/** @type {import('jest').Config} */
module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/test'],
  testMatch: ['**/*.tests.js', '**/*.test.js', '**/*.test.ts', '**/*.test.mjs'],
  moduleNameMapper: {
    '^(\\.{1,2}/.*)\\.js$': '$1',
  },
  extensionsToTreatAsEsm: ['.ts'],
  coverageDirectory: 'coverage',
  collectCoverageFrom: [
    'src/**/*.ts',
    '!src/**/*.d.ts',
    '!src/types/**',
    '!test/**'
  ],
  coverageThreshold: {
    global: {
      branches: 95,
      functions: 100,
      lines: 95,
      statements: 95
    }
  },
  testTimeout: 10000,
  setupFilesAfterEnv: ['<rootDir>/test/setup.ts'],
  moduleFileExtensions: ['ts', 'js', 'mjs', 'json', 'node'],
  transform: {
    '^.+\\.js$': ['ts-jest', {
      allowJs: true,
      tsconfig: {
        allowJs: true,
        checkJs: false,
        strict: false
      }
    }],
    '^.+\\.mjs$': ['ts-jest', {
      allowJs: true,
      tsconfig: {
        allowJs: true,
        checkJs: false,
        strict: false,
        module: 'esnext'
      }
    }],
    '^.+\\.ts$': ['ts-jest', {
      useESM: true,
      isolatedModules: true,
      tsconfig: {
        allowJs: false,
        strict: true
      }
    }]
  },
};