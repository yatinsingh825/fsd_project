module.exports = {
  // Use the MongoDB preset
  preset: '@shelf/jest-mongodb',
  // Stop on the first test failure
  bail: 1,
  // Show detailed test results
  verbose: true,
  // Set a longer timeout for database operations
  testTimeout: 30000,
  // Tell Jest to look for tests in a __tests__ folder
  testMatch: ['**/__tests__/**/*.test.js'],
  // Set the node environment to 'test'
  setupFilesAfterEnv: ['<rootDir>/jest.setup.js'],
};
