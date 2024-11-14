require('dotenv').config();  // Ensure dotenv is loaded at the top
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = 3000;

// Check if JWT_SECRET is loaded correctly
console.log("JWT_SECRET:", process.env.JWT_SECRET);

// MongoDB connection URI
const mongoURI = 'mongodb+srv://Megavathi:nn3bE57OSHL2mroB@cluster0.zjdbh.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0';

// Connect to MongoDB
mongoose.connect(mongoURI)
    .then(() => {
        console.log('Connected to MongoDB');
    })
    .catch(err => {
        console.error('Error connecting to MongoDB:', err);
    });

// Middleware to parse JSON data
app.use(express.json());

// Define a Schema and Model for a "User"
const userSchema = new mongoose.Schema({
    name: String,
    age: Number,
    email: { type: String, unique: true },
    password: { type: String, required: true },
});

// Hash the password before saving it to the database
userSchema.pre('save', async function (next) {
    if (this.isModified('password')) {
        this.password = await bcrypt.hash(this.password, 10);
    }
    next();
});

const User = mongoose.model('User', userSchema);

// Generate JWT Token
const generateToken = (user) => {
    if (!process.env.JWT_SECRET) {
        throw new Error('JWT_SECRET is not defined in environment variables.');
    }
    return jwt.sign({ id: user._id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '24h' });
};

// Middleware for Authorization (JWT Verification)
const authenticate = (req, res, next) => {
    const token = req.headers['authorization'];  // Get the Authorization header
    if (!token) {
        return res.status(401).json({
            success: false,
            message: 'No token provided'
        });
    }

    // Ensure token is prefixed with 'Bearer'
    if (!token.startsWith('Bearer ')) {
        return res.status(401).json({
            success: false,
            message: 'Invalid token format, token must be prefixed with "Bearer "'
        });
    }

    // Extract the actual JWT token part (after "Bearer ")
    const actualToken = token.split(' ')[1];

    // Verify JWT Token
    jwt.verify(actualToken, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(401).json({
                success: false,
                message: 'Failed to authenticate token'
            });
        }
        req.user = decoded;  // Store decoded user info in the request object
        next();  // Proceed to the next middleware or route handler
    });
};

/** 
 * 1. POST - Register a New User
 * Endpoint: /api/users/register
 */
app.post('/api/users/register', async (req, res) => {
    const { name, age, email, password } = req.body;

    try {
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({
                success: false,
                message: 'Email already exists'
            });
        }

        const newUser = new User({ name, age, email, password });
        await newUser.save();

        const token = generateToken(newUser);
        res.status(201).json({
            success: true,
            message: 'User created successfully',
            data: newUser,
            token
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Failed to create user',
            error: error.message
        });
    }
});

/** 
 * 2. POST - Login User
 * Endpoint: /api/users/login
 */
app.post('/api/users/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({
                success: false,
                message: 'User not found'
            });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({
                success: false,
                message: 'Incorrect password'
            });
        }

        const token = generateToken(user);
        res.json({
            success: true,
            message: 'Login successful',
            token
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Login failed',
            error: error.message
        });
    }
});
 
 /** 
 * 3. POST - Refresh Token
 * Endpoint: /api/users/refresh-token
 */
app.get('/api/users/refresh-token',authenticate, async (req, res) => {
    const { token } = req.body;  // Incoming refresh token
    
    if (!token) {
        return res.status(400).json({
            success: false,
            message: 'No refresh token provided'
        });
    }

    try {
        // Verify the refresh token
        const decoded = jwt.verify(token, process.env.JWT_SECRET_REFRESH); // You can use a different secret for refresh token
        const user = await User.findById(decoded.id);

        if (!user) {
            return res.status(401).json({
                success: false,
                message: 'Invalid refresh token'
            });
        }

        // Generate a new access token
        const newToken = generateToken(user);  // Reuse the generateToken function

        return res.json({
            success: true,
            token: newToken
        });
    } catch (error) {
        return res.status(500).json({
            success: false,
            message: 'Failed to refresh token',
            error: error.message
        });
    }
});

/** 
 * 1. GET - Retrieve All Users
 * Endpoint: /api/users
 */
app.get('/api/users',authenticate, async (req, res) => {
    try {
      const users = await User.find(); // Fetch users from MongoDB
      
  
      res.json({
        success: true,
        data: users,
      });
    } catch (error) {
      console.error('Database fetch error:', error.message); // Log specific database error
      res.status(500).json({
        success: false,
        message: 'Failed to fetch users',
        error: error.message,
      });
    }
  });
  
/** 
 * 2. POST - Create a New User (Requires JWT Token)
 * Endpoint: /api/users
 */
app.post('/api/users', authenticate, async (req, res) => {
    const { name, age, email } = req.body;

    try {
        const newUser = new User({ name, age, email });
        await newUser.save();  // Save the new user to MongoDB
        res.status(201).json({
            success: true,
            message: 'User created successfully',
            data: newUser
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Failed to create user',
            error: error.message
        });
    }
});

/** 
 * 3. PUT - Update a User by ID (Requires JWT Token)
 * Endpoint: /api/users/:id
 */
app.put('/api/users/:id', authenticate, async (req, res) => {
    const userId = req.params.id;
    const { name, age, email } = req.body;

    try {
        const updatedUser = await User.findByIdAndUpdate(userId, { name, age, email }, { new: true });
        if (!updatedUser) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }
        res.json({
            success: true,
            message: 'User updated successfully',
            data: updatedUser
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Failed to update user',
            error: error.message
        });
    }
});

/** 
 * 4. DELETE - Remove a User by ID (Requires JWT Token)
 * Endpoint: /api/users/:id
 */
app.delete('/api/users/:id', authenticate, async (req, res) => {
    const userId = req.params.id;

    try {
        const deletedUser = await User.findByIdAndDelete(userId);
        if (!deletedUser) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }
        res.json({
            success: true,
            message: 'User deleted successfully',
            data: deletedUser
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Failed to delete user',
            error: error.message
        });
    }
});

// Start the server
app.listen(PORT, () => {
    console.log(`Server is running on http://192.168.0.144:${PORT}`);
});
