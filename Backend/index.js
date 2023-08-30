import express from "express";
import mysql from "mysql2";
import jwt from "jsonwebtoken";
import bcrypt from 'bcrypt';
import cors from "cors";
import dotenv from 'dotenv';

dotenv.config();

const app = express();
app.use(express.json());
app.use(cors());

const db = mysql.createConnection({
    host: "localhost",
    user: "root",
    password: process.env.DB_PASSWORD,  // Use environment variable
    database: "interactive_posts"
});

const SALT_ROUNDS = 10;

// Registration Endpoint
app.post('/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        if (!username || !password) {
            return res.status(400).send('Username and password required');
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

        // Store user in the database
        const [rows] = await db.promise().execute('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashedPassword]);

        // Send success response
        res.status(201).send({ message: 'User registered', userId: rows.insertId });
    } catch (error) {
        res.status(500).send({ error: 'Server error' });
    }
});

// Login Endpoint
app.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        if (!username || !password) {
            return res.status(400).send('Username and password required');
        }

        // Get user from the database
        const [users] = await db.promise().execute('SELECT * FROM users WHERE username = ?', [username]);
        const user = users[0];

        if (!user) {
            return res.status(400).send('Invalid credentials');
        }

        // Check the password
        const isPasswordValid = await bcrypt.compare(password, user.password);

        if (!isPasswordValid) {
            return res.status(400).send('Invalid credentials');
        }

        // Create a JWT token
        const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });

        res.status(200).send({ message: 'Logged in', token });
    } catch (error) {
        res.status(500).send({ error: 'Server error' });
    }
});

// Middleware to Protect Routes
const verifyToken = (req, res, next) => {
    const token = req.headers['authorization'];

    if (!token) {
        return res.status(403).send({ message: 'No token provided' });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(401).send({ message: 'Failed to authenticate token' });
        }

        // Add user id to request
        req.userId = decoded.userId;
        next();
    });
};

app.get('/some-protected-route', verifyToken, async (req, res) => {
    try {
        // Fetching username using userId
        const [rows] = await db.promise().execute('SELECT username FROM users WHERE id = ?', [req.userId]);
        
        // If no user found with the provided userId (this should ideally never happen if your JWT is valid)
        if (rows.length === 0) {
            return res.status(404).send({ message: 'User not found' });
        }

        // Extract the username from the result
        const { username } = rows[0];

        // Send the username in the response
        res.send({ message: "This is a protected route", username });

    } catch (error) {
        res.status(500).send({ error: 'Server error' });
    }
});


const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});

