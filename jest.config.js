/** @type {import('jest').Config} */
module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/test'],
  testMatch: ['**/*.tests.js', '**/*.test.js'],
  coverageDirectory: 'coverage',
  collectCoverageFrom: [
    'index.js',
    'sign.js',
    'verify.js',
    'decode.js',
    'lib/**/*.js',
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
  setupFilesAfterEnv: ['<rootDir>/test/setup.js'],
  moduleFileExtensions: ['js', 'json', 'node'],
  transform: {
    '^.+\\.js$': ['ts-jest', {
      allowJs: true,
      tsconfig: {
        allowJs: true,
        checkJs: false,
        strict: false
      }
    }]
  },
  globals: {
    'ts-jest': {
      diagnostics: {
        warnOnly: true
      }
    }
  }
};