const request = require('supertest');
const app = require('../server'); // Import your app
const mongoose = require('mongoose');
const User = mongoose.model('User'); // Import your User model

describe('Auth Routes', () => {
  
  it('should register a new viewer successfully', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .send({
        username: 'testviewer',
        password: 'password123',
        role: 'Viewer',
      });

    // Check for a successful HTTP status
    expect(res.statusCode).toEqual(200);
    // Check that we got an access token and user object
    expect(res.body).toHaveProperty('accessToken');
    expect(res.body.user.username).toBe('testviewer');
    expect(res.body.user.role).toBe('Viewer');
    
    // Check that the user was actually saved to the DB with a hashed password
    const user = await User.findOne({ username: 'testviewer' });
    expect(user).toBeTruthy();
    expect(user.password).not.toBe('password123'); // Ensure it's hashed
  });

  it('should fail to register with a duplicate username', async () => {
    // First, create the user
    await request(app)
      .post('/api/auth/register')
      .send({
        username: 'testuser',
        password: 'password123',
        role: 'Editor',
      });

    // Then, try to create it again
    const res = await request(app)
      .post('/api/auth/register')
      .send({
        username: 'testuser',
        password: 'password123',
        role: 'Viewer',
      });

    // Check for the 400 Bad Request error
    expect(res.statusCode).toEqual(400);
    expect(res.body.message).toBe('User already exists.');
  });
  
  it('should log in an existing user successfully', async () => {
    // Register the user first
    await request(app)
      .post('/api/auth/register')
      .send({
        username: 'testlogin',
        password: 'password123',
        role: 'Editor',
      });

    // Now, log in
    const res = await request(app)
      .post('/api/auth/login')
      .send({
        username: 'testlogin',
        password: 'password123',
      });

    expect(res.statusCode).toEqual(200);
    expect(res.body).toHaveProperty('accessToken');
    expect(res.body.user.role).toBe('Editor');
    // Check for the httpOnly cookie
    expect(res.headers['set-cookie'][0]).toContain('refreshToken');
  });

  it('should fail to log in with a wrong password', async () => {
    // Register the user first
    await request(app)
      .post('/api/auth/register')
      .send({
        username: 'wrongpass',
        password: 'password123',
        role: 'Viewer',
      });

    // Now, try to log in with the wrong password
    const res = await request(app)
      .post('/api/auth/login')
      .send({
        username: 'wrongpass',
        password: 'wrongpassword',
      });

    expect(res.statusCode).toEqual(400);
    expect(res.body.message).toBe('Invalid credentials.');
  });
});
