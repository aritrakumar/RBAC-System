// Import necessary modules
const express = require('express')
const jwt = require('jsonwebtoken')
const bcrypt = require('bcryptjs')
const sqlite3 = require('sqlite3').verbose()
const { open } = require('sqlite')
const { body, validationResult } = require('express-validator')

// Initialize Express app
const app = express()
app.use(express.json())

const SECRET_KEY = 'your_secret_key'

// Initialize SQLite database
let db
;(async () => {
    db = await open({
        filename: './rbac_system.db',
        driver: sqlite3.Database,
    })
    await db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )`)
    await db.run(`CREATE TABLE IF NOT EXISTS roles (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL
    )`)
    await db.run(`CREATE TABLE IF NOT EXISTS user_roles (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        role_id INTEGER NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id),
        FOREIGN KEY(role_id) REFERENCES roles(id)
    )`)
    // Adding default roles if they do not exist
    const roles = ['Admin', 'User', 'Moderator']
    for (const role of roles) {
        const roleExists = await db.get(
            'SELECT * FROM roles WHERE name = ?',
            role
        )
        if (!roleExists) {
            await db.run('INSERT INTO roles (name) VALUES (?)', role)
        }
    }
})()

// Middleware to verify token
const tokenRequired = (req, res, next) => {
    const token = req.headers['x-access-token']
    if (!token) {
        return res.status(403).json({ message: 'Token is missing!' })
    }
    try {
        const decoded = jwt.verify(token, SECRET_KEY)
        req.userId = decoded.userId
        next()
    } catch (err) {
        return res.status(403).json({ message: 'Token is invalid!' })
    }
}

// Middleware for role-based access control
const roleRequired = requiredRole => {
    return async (req, res, next) => {
        try {
            const userRoles = await db.all(
                'SELECT r.name FROM user_roles ur JOIN roles r ON ur.role_id = r.id WHERE ur.user_id = ?',
                req.userId
            )
            const roleNames = userRoles.map(role => role.name)
            if (!roleNames.includes(requiredRole)) {
                return res
                    .status(403)
                    .json({
                        message:
                            'You do not have permission to access this resource!',
                    })
            }
            next()
        } catch (err) {
            res.status(500).json({ message: 'Server error' })
        }
    }
}

// User registration route
app.post(
    '/register',
    body('username').isString().notEmpty().withMessage('Username is required'),
    body('password')
        .isLength({ min: 6 })
        .withMessage('Password must be at least 6 characters long'),
    async (req, res) => {
        const errors = validationResult(req)
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() })
        }
        try {
            const { username, password } = req.body
            const hashedPassword = await bcrypt.hash(password, 10)
            await db.run(
                'INSERT INTO users (username, password) VALUES (?, ?)',
                username,
                hashedPassword
            )
            res.status(201).json({ message: 'User registered successfully!' })
        } catch (err) {
            res.status(400).json({ message: 'Error registering user' })
        }
    }
)

// User login route
app.post(
    '/login',
    body('username').isString().notEmpty().withMessage('Username is required'),
    body('password').isString().notEmpty().withMessage('Password is required'),
    async (req, res) => {
        const errors = validationResult(req)
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() })
        }
        try {
            const { username, password } = req.body
            const user = await db.get(
                'SELECT * FROM users WHERE username = ?',
                username
            )
            if (user && (await bcrypt.compare(password, user.password))) {
                const token = jwt.sign({ userId: user.id }, SECRET_KEY, {
                    expiresIn: '1h',
                })
                res.json({ token })
            } else {
                res.status(401).json({
                    message: 'Invalid username or password!',
                })
            }
        } catch (err) {
            res.status(500).json({ message: 'Server error' })
        }
    }
)

// Route to assign role to user
app.post(
    '/assign_role',
    tokenRequired,
    body('username').isString().notEmpty().withMessage('Username is required'),
    body('role').isString().notEmpty().withMessage('Role is required'),
    async (req, res) => {
        const errors = validationResult(req)
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() })
        }
        try {
            const { username, role } = req.body
            const user = await db.get(
                'SELECT * FROM users WHERE username = ?',
                username
            )
            const roleObj = await db.get(
                'SELECT * FROM roles WHERE name = ?',
                role
            )
            if (!user || !roleObj) {
                return res
                    .status(404)
                    .json({ message: 'User or role not found!' })
            }
            await db.run(
                'INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)',
                user.id,
                roleObj.id
            )
            res.status(201).json({ message: 'Role assigned successfully!' })
        } catch (err) {
            res.status(500).json({ message: 'Server error' })
        }
    }
)

// Protected route for Admin
app.get('/admin', tokenRequired, roleRequired('Admin'), async (req, res) => {
    res.json({ message: 'Welcome, you have admin access.' })
})

// Protected route for Moderator
app.get(
    '/moderator',
    tokenRequired,
    roleRequired('Moderator'),
    async (req, res) => {
        res.json({ message: 'Welcome, you have moderator access.' })
    }
)

// Protected route for User
app.get('/user', tokenRequired, roleRequired('User'), async (req, res) => {
    res.json({ message: 'Welcome, you have user access.' })
})

// Logout route
app.post('/logout', tokenRequired, (req, res) => {
    // To "log out" the user, the client should simply discard the JWT.
    // Here, we return a response to indicate logout is successful.
    res.json({ message: 'User logged out successfully!' })
})

// Start the server
app.listen(3000, () => {
    console.log('Server running on port 3000')
})
