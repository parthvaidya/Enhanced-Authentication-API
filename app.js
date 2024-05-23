//import necessary modules
const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const database = require('./database');
const bcrypt = require('bcrypt');
// const { ClerkExpressWithAuth , redirectToSignIn, handleOAuthCallback } = require('@clerk/clerk-sdk-node');

const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
const JWT_SECRET = 'custom_secret_key';

app.use(bodyParser.json());
// app.use(ClerkExpressWithAuth ({
//   apiKey: process.env.CLERK_PUBLISHABLE_KEY,
//   apiSecretKey: process.env.CLERK_SECRET_KEY,

// }));
const upload = multer({ dest: 'uploads/' });
 


const authenticateUser = (req, res, next) => {
    // Check if Authorization  is there
    const authHeader = req.headers.authorization;
    if (!authHeader) {
      return res.status(401).json({ error: 'Authorization header missing' });
    }
  
    // Verifying JWT token
    const token = authHeader.split(' ')[1];
    jwt.verify(token, JWT_SECRET, (err, user) => {
      if (err) {
        return res.status(403).json({ error: 'Invalid token' });
      }
      req.user = user;
      next();
    });
  };
  
  // register new user using details
  app.post('/register', async (req, res) => {
    try {
      const { name, phoneNumber, email, password } = req.body;
      const hashedPassword = await bcrypt.hash(password, 10);
      await database('users').insert({ name, phoneNumber, email, password: hashedPassword });
      res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });

  
  
  app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await database('users').where({ email }).first();
        if (!user) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }
        const token = jwt.sign({ id: user.id, isAdmin: user.isAdmin }, JWT_SECRET);
        res.json({ message: 'Login successful', token: token }); 
    } catch (error) {
        res.status(500).json({ error: 'Failed to login' });
    }
});

app.get('/profile', authenticateUser, async (req, res) => {
    try {
        const userProfile = await database('users').where({ id: req.user.id }).first();
        if (!userProfile) {
            return res.status(404).json({ error: 'User profile not found' });
        }
        res.json(userProfile);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch user profile' });
    }
});

app.put('/profile', authenticateUser, upload.single('photo'), async (req, res) => {
    try {
        const { name, bio, phoneNumber, email, password, isPublic } = req.body;
        const updatedFields = { name, bio, phoneNumber, email, isPublic };

        if (password) {
            const hashedPassword = await bcrypt.hash(password, 10);
            updatedFields.password = hashedPassword;
        }

        if (req.file) {
            updatedFields.photo = req.file.path;
        } else if (req.body.photoUrl) {
            updatedFields.photo = req.body.photoUrl;
        }

        await database('users').where({ id: req.user.id }).update(updatedFields);
        res.json({ message: 'Profile updated successfully' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to update profile' });
    }
});

app.get('/users', authenticateUser, async (req, res) => {
    try {
        let users;
        if (req.user.isAdmin) {
            users = await database('users').select();
        } else {
            users = await database('users').where({ isPublic: true }).select();
        }
        res.json(users);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch users' });
    }
});



// Start the server
const PORT = process.env.PORT || 3000;
const server = app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});