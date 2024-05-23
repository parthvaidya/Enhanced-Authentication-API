const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const database = require('./database');
const passport = require('passport');
const bcrypt = require('bcrypt');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const GitHubStrategy = require('passport-github').Strategy;
const TwitterStrategy = require('passport-twitter').Strategy;

const app = express();
const JWT_SECRET = 'custom_secret_key';
const GOOGLE_CLIENT_ID = 'your_google_client_id'; // Replace with your Google client ID
const GOOGLE_CLIENT_SECRET = 'your_google_client_secret'; // Replace with your Google client secret
const FACEBOOK_APP_ID = 'your_facebook_app_id'; // Replace with your Facebook app ID
const FACEBOOK_APP_SECRET = 'your_facebook_app_secret'; // Replace with your Facebook app secret
const GITHUB_CLIENT_ID = 'your_github_client_id'; // Replace with your GitHub client ID
const GITHUB_CLIENT_SECRET = 'your_github_client_secret'; // Replace with your GitHub client secret
const TWITTER_CONSUMER_KEY = 'your_twitter_consumer_key'; // Replace with your Twitter consumer key
const TWITTER_CONSUMER_SECRET = 'your_twitter_consumer_secret';
app.use(bodyParser.json());

passport.serializeUser((user, done) => {
    done(null, user);
  });
  
  passport.deserializeUser((user, done) => {
    done(null, user);
  });

  // Google OAuth 2.0 strategy
passport.use(new GoogleStrategy({
    clientID: GOOGLE_CLIENT_ID,
    clientSecret: GOOGLE_CLIENT_SECRET,
    callbackURL: '/auth/google/callback'
  },
  async (accessToken, refreshToken, profile, done) => {
    try {
      // Check if user exists in the database
      let user = await database('users').where({ email: profile.emails[0].value }).first();
      if (!user) {
        // If user doesn't exist, create a new user record
        user = await database('users').insert({ name: profile.displayName, email: profile.emails[0].value });
      }
      return done(null, user);
    } catch (error) {
      return done(error);
    }
  }));
  
  // Facebook OAuth 2.0 strategy
  passport.use(new FacebookStrategy({
    clientID: FACEBOOK_APP_ID,
    clientSecret: FACEBOOK_APP_SECRET,
    callbackURL: '/auth/facebook/callback',
    profileFields: ['id', 'emails', 'displayName']
  },
  async (accessToken, refreshToken, profile, done) => {
    try {
      // Check if user exists in the database
      let user = await database('users').where({ email: profile.emails[0].value }).first();
      if (!user) {
        // If user doesn't exist, create a new user record
        user = await database('users').insert({ name: profile.displayName, email: profile.emails[0].value });
      }
      return done(null, user);
    } catch (error) {
      return done(error);
    }
  }));
  
  // GitHub OAuth 2.0 strategy
  passport.use(new GitHubStrategy({
    clientID: GITHUB_CLIENT_ID,
    clientSecret: GITHUB_CLIENT_SECRET,
    callbackURL: '/auth/github/callback'
  },
  async (accessToken, refreshToken, profile, done) => {
    try {
      // Check if user exists in the database
      let user = await database('users').where({ email: profile.emails[0].value }).first();
      if (!user) {
        // If user doesn't exist, create a new user record
        user = await database('users').insert({ name: profile.displayName, email: profile.emails[0].value });
      }
      return done(null, user);
    } catch (error) {
      return done(error);
    }
  }));
  
  // Twitter OAuth 1.0 strategy
  passport.use(new TwitterStrategy({
    consumerKey: TWITTER_CONSUMER_KEY,
    consumerSecret: TWITTER_CONSUMER_SECRET,
    callbackURL: '/auth/twitter/callback'
  },
  async (token, tokenSecret, profile, done) => {
    try {
      // Check if user exists in the database
      let user = await database('users').where({ email: profile.emails[0].value }).first();
      if (!user) {
        // If user doesn't exist, create a new user record
        user = await database('users').insert({ name: profile.displayName, email: profile.emails[0].value });
      }
      return done(null, user);
    } catch (error) {
      return done(error);
    }
  }));
  
 


const authenticateUser = (req, res, next) => {
    // Check if Authorization header is present
    const authHeader = req.headers.authorization;
    if (!authHeader) {
      return res.status(401).json({ error: 'Authorization header missing' });
    }
  
    // Verify JWT token
    const token = authHeader.split(' ')[1];
    jwt.verify(token, JWT_SECRET, (err, user) => {
      if (err) {
        return res.status(403).json({ error: 'Invalid token' });
      }
      req.user = user;
      next();
    });
  };
  
  // Routes
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
      res.json({ message: 'Login successful' });
      
    } catch (error) {
      res.status(500).json({ error: 'Failed to login' });
    }
  });


  // Route for user login using Google OAuth 2.0
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/login' }),
  (req, res) => {
    const user = req.user;
    const token = jwt.sign({ id: user.id, isAdmin: user.isAdmin }, JWT_SECRET);
    res.json({ token });
  });

// Route for user login using Facebook OAuth 2.0
app.get('/auth/facebook', passport.authenticate('facebook', { scope: ['email'] }));

app.get('/auth/facebook/callback',
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  (req, res) => {
    const user = req.user;
    const token = jwt.sign({ id: user.id, isAdmin: user.isAdmin }, JWT_SECRET);
    res.json({ token });
  });

// Route for user login using GitHub OAuth 2.0
app.get('/auth/github', passport.authenticate('github', { scope: ['user:email'] }));

app.get('/auth/github/callback',
  passport.authenticate('github', { failureRedirect: '/login' }),
  (req, res) => {
    const user = req.user;
    const token = jwt.sign({ id: user.id, isAdmin: user.isAdmin }, JWT_SECRET);
    res.json({ token });
  });

// Route for user login using Twitter OAuth 1.0
app.get('/auth/twitter', passport.authenticate('twitter'));

app.get('/auth/twitter/callback',
  passport.authenticate('twitter', { failureRedirect: '/login' }),
  (req, res) => {
    const user = req.user;
    const token = jwt.sign({ id: user.id, isAdmin: user.isAdmin }, JWT_SECRET);
    res.json({ token });
  });
  
  app.get('/profile', authenticateUser, async (req, res) => {
    try {
      const userId = req.user.id;
      const userProfile = await database('users').where({ id: userId }).first();
      if (!userProfile) {
        return res.status(404).json({ error: 'User profile not found' });
      }
      res.json(userProfile);
    } catch (error) {
      res.status(500).json({ error: 'Failed to fetch user profile' });
    }
  });
  
  app.put('/profile', authenticateUser, async (req, res) => {
    try {
      const userId = req.user.id;
      const { name, phoneNumber, email, bio, photoUrl, password, isPublic } = req.body;
      // Update user profile based on provided data
      await database('users').where({ id: userId }).update({ name, phoneNumber, email, bio, photoUrl, password, isPublic });
      res.json({ message: 'User profile updated successfully' });
    } catch (error) {
      res.status(500).json({ error: 'Failed to update user profile' });
    }
  });
  
  app.get('/public_profiles', async (req, res) => {
    try {
      const publicProfiles = await database('users').where({ isPublic: true }).select('id', 'name', 'bio', 'photoUrl');
      res.json(publicProfiles);
    } catch (error) {
      res.status(500).json({ error: 'Failed to fetch public profiles' });
    }
  });
  
  // Admin-only route to get all user profiles (both public and private)
  app.get('/admin/all_profiles', authenticateUser, async (req, res) => {
    try {
      if (!req.user.isAdmin) {
        return res.status(403).json({ error: 'Unauthorized' });
      }
      const allProfiles = await database('users').select('id', 'name', 'bio', 'photoUrl', 'isPublic');
      res.json(allProfiles);
    } catch (error) {
      res.status(500).json({ error: 'Failed to fetch user profiles' });
    }
  });

// Start the server
const PORT = process.env.PORT || 3000;
const server = app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});