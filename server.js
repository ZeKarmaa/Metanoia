const express = require('express');
const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const app = express();
const PORT = 3000;
const SECRET_KEY = 'your-secret-key-change-this';
const DB_FILE = path.join(__dirname, 'database.json');
const ROLES = { ADMIN: 'Admin', MEMBER: 'Member' };
const SUBROLES = { ADMIN: ['Trial', 'Regular', 'Coordonator', 'Organizer', 'Overseer', 'Deputy', 'Leader'], MEMBER: ['Recruit', 'Corporal', 'Sergeant', 'Lieutenant', 'Captain', 'General'] };
app.use(express.json());
app.use(cors());
function readDatabase() {
    try {
        if (!fs.existsSync(DB_FILE)) {
            return { users: [], admins: [] };
        }
        return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
    } catch (error) {
        console.error('Error reading database:', error);
        return { users: [], admins: [] };
    }
}
function saveDatabase(data) {
    try {
        fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2), 'utf8');
        console.log('Database saved successfully');
    } catch (error) {
        console.error('Error saving database:', error);
    }
}
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) {
        return res.status(401).json({ error: 'No token provided' });
    }
    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid token' });
        }
        req.user = user;
        next();
    });
}
app.post('/api/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        const db = readDatabase();
        if (db.admins.some(a => a.username === username)) {
            return res.status(400).json({ error: 'Admin already exists' });
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        db.admins.push({ username, password: hashedPassword, role: ROLES.ADMIN, subrole: SUBROLES.ADMIN[0], createdAt: new Date().toISOString() });
        saveDatabase(db);
        res.json({ message: 'Admin registered successfully' });
    } catch (error) {
        res.status(500).json({ error: 'Registration failed' });
    }
});
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const db = readDatabase();
        const admin = db.admins.find(a => a.username === username);
        if (!admin || !(await bcrypt.compare(password, admin.password))) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        const token = jwt.sign({ username, role: admin.role, subrole: admin.subrole }, SECRET_KEY, { expiresIn: '24h' });
        res.json({ token, role: admin.role, subrole: admin.subrole });
    } catch (error) {
        res.status(500).json({ error: 'Login failed' });
    }
});
app.get('/api/users', authenticateToken, (req, res) => {
    const db = readDatabase();
    res.json(db.users);
});
app.post('/api/users', authenticateToken, (req, res) => {
    try {
        const { name, role, subrole } = req.body;
        const db = readDatabase();
        if (!Object.values(ROLES).includes(role)) {
            return res.status(400).json({ error: 'Invalid role' });
        }
        const validSubroles = role === ROLES.ADMIN ? SUBROLES.ADMIN : SUBROLES.MEMBER;
        if (!validSubroles.includes(subrole)) {
            return res.status(400).json({ error: 'Invalid subrole for this role' });
        }
        if (db.users.some(u => u.name === name)) {
            return res.status(400).json({ error: 'User already exists' });
        }
        const newUser = { id: Date.now(), name, points: 0, role, subrole, createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() };
        db.users.push(newUser);
        saveDatabase(db);
        res.json({ message: 'User added successfully', user: newUser });
    } catch (error) {
        res.status(500).json({ error: 'Failed to add user' });
    }
});
app.put('/api/users/:id/points', authenticateToken, (req, res) => {
    try {
        const { points } = req.body;
        const db = readDatabase();
        const user = db.users.find(u => u.id === parseInt(req.params.id));
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        user.points += points;
        user.updatedAt = new Date().toISOString();
        saveDatabase(db);
        res.json({ message: 'Points updated successfully', user });
    } catch (error) {
        res.status(500).json({ error: 'Failed to update points' });
    }
});
app.put('/api/users/:id/role', authenticateToken, (req, res) => {
    try {
        const { role, subrole } = req.body;
        const db = readDatabase();
        const user = db.users.find(u => u.id === parseInt(req.params.id));
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        if (!Object.values(ROLES).includes(role)) {
            return res.status(400).json({ error: 'Invalid role' });
        }
        const validSubroles = role === ROLES.ADMIN ? SUBROLES.ADMIN : SUBROLES.MEMBER;
        if (!validSubroles.includes(subrole)) {
            return res.status(400).json({ error: 'Invalid subrole for this role' });
        }
        user.role = role;
        user.subrole = subrole;
        user.updatedAt = new Date().toISOString();
        saveDatabase(db);
        res.json({ message: 'Role updated successfully', user });
    } catch (error) {
        res.status(500).json({ error: 'Failed to update role' });
    }
});
app.delete('/api/users/:id', authenticateToken, (req, res) => {
    try {
        const db = readDatabase();
        const index = db.users.findIndex(u => u.id === parseInt(req.params.id));
        if (index === -1) {
            return res.status(404).json({ error: 'User not found' });
        }
        const deletedUser = db.users.splice(index, 1);
        saveDatabase(db);
        res.json({ message: 'User deleted successfully', user: deletedUser[0] });
    } catch (error) {
        res.status(500).json({ error: 'Failed to delete user' });
    }
});
app.get('/api/roles', authenticateToken, (req, res) => {
    res.json({ roles: Object.values(ROLES), subroles: SUBROLES });
});
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
