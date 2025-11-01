const request = require('supertest');
const app = require('../server'); // Import your app
const mongoose = require('mongoose');

// Helper function to register and log in a user of a specific role
async function loginAs(role) {
  const username = `${role.toLowerCase()}user`;
  const password = 'password123';

  // Register
  await request(app)
    .post('/api/auth/register')
    .send({ username, password, role });

  // Login
  const res = await request(app)
    .post('/api/auth/login')
    .send({ username, password });
  
  return res.body.accessToken; // Return the auth token
}

describe('Content Routes RBAC', () => {

  it('should ALLOW an Editor to create content', async () => {
    const editorToken = await loginAs('Editor');

    const res = await request(app)
      .post('/api/content')
      .set('Authorization', `Bearer ${editorToken}`) // Set the auth header
      .send({
        title: 'Editor Post',
        body: 'This is a post by an editor.',
      });

    expect(res.statusCode).toEqual(201); // 201 Created
    expect(res.body.title).toBe('Editor Post');
  });

  it('should FORBID a Viewer from creating content', async () => {
    const viewerToken = await loginAs('Viewer');

    const res = await request(app)
      .post('/api/content')
      .set('Authorization', `Bearer ${viewerToken}`) // Set the auth header
      .send({
        title: 'Viewer Post',
        body: 'This post should not be created.',
      });

    // This is the crucial test for your authorize middleware
    expect(res.statusCode).toEqual(403); // 403 Forbidden
    expect(res.body.message).toBe('Forbidden: You do not have permission.');
  });

  it("should ALLOW an Admin to delete an Editor's post", async () => {
    const editorToken = await loginAs('Editor');
    const adminToken = await loginAs('Admin'); // This works because we modified server.js

    // 1. Editor creates a post
    const postRes = await request(app)
      .post('/api/content')
      .set('Authorization', `Bearer ${editorToken}`)
      .send({ title: 'Post to be deleted', body: '...' });
    
    const postId = postRes.body._id;

    // 2. Admin deletes that post
    const deleteRes = await request(app)
      .delete(`/api/content/${postId}`)
      .set('Authorization', `Bearer ${adminToken}`); // Use Admin token

    expect(deleteRes.statusCode).toEqual(200);
    expect(deleteRes.body.message).toBe('Content deleted successfully.');
  });
  
});
