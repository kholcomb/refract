/** @type {import('ts-jest').JestConfigWithTsJest} */
module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/tests'],
  testMatch: ['<rootDir>/tests/*.test.ts'],
  testPathIgnorePatterns: ['/node_modules/', '/tests/fixtures/'],
  collectCoverageFrom: ['src/**/*.ts', '!src/index.ts'],
  coverageDirectory: 'coverage',
  moduleFileExtensions: ['ts', 'js', 'json'],
  moduleNameMapper: {
    '^@refract/core$': '<rootDir>/../core/src/index.ts',
  },
};
