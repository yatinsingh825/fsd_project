const mongoose = require('mongoose');

// Set a longer timeout for all tests
jest.setTimeout(30000);

// Before all tests, connect to the in-memory database
beforeAll(async () => {
  // The MONGO_URI is automatically set by @shelf/jest-mongodb
  await mongoose.connect(process.env.MONGO_URI);
});

// After each test, clear all data
afterEach(async () => {
  const collections = mongoose.connection.collections;
  for (const key in collections) {
    await collections[key].deleteMany({});
  }
});

// After all tests, disconnect from the database
afterAll(async () => {
  await mongoose.disconnect();
});
