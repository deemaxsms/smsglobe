const express = require('express');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const path = require('path'); // Added for file path handling

dotenv.config();
const app = express();

app.use(cors());
app.use(express.json());

// --- 1. SERVE STATIC FILES (Essential for Vercel) ---
// This tells Express to serve your .html, .css, and .js files automatically
app.use(express.static(__dirname)); 

// Change this to match the new filename
app.get('/smsadmin/sms_login', (req, res) => {
    res.sendFile(path.join(__dirname, 'smsadmin', 'sms_login.html'));
});

// Ensure this is still there to catch the other files (sms_create, sms_forgot)
app.use('/smsadmin', express.static(path.join(__dirname, 'smsadmin')));

// --- 2. CONFIGURATION & SCHEMA ---
const JWT_SECRET = process.env.JWT_SECRET;

const adminSchema = new mongoose.Schema({
    fullName: { type: String, required: true },
    email: { type: String, required: true, unique: true, index: true },
    password: { type: String, required: true },
}, { timestamps: true });

const Admin = mongoose.models.Admin || mongoose.model('Admin', adminSchema);

// --- 3. OPTIMIZED MONGOOSE CONNECTION ---
let isConnected = false;
const connectDB = async () => {
    if (isConnected) return;
    try {
        await mongoose.connect(process.env.MONGODB_URI, {
            maxPoolSize: 100, 
            serverSelectionTimeoutMS: 5000,
            socketTimeoutMS: 45000,
        });
        isConnected = true;
    } catch (err) {
        console.error("DB Error:", err);
    }
};

// --- 4. CACHING ---
let localCache = { data: null, lastFetched: 0 };

// --- 5. MIDDLEWARE ---
const verifyToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(403).json({ success: false, error: "No token provided" });
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        return res.status(401).json({ success: false, error: "Unauthorized" });
    }
};

// --- 6. ROUTES ---

// NEW: This handles the "/" error by serving index.html
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// The Central Switch-Case Controller for API
app.all('/api/:action', async (req, res) => {
    await connectDB();
    const action = req.params.action;

    switch (action) {
        case 'login': return handleLogin(req, res);
        case 'register': return handleRegister(req, res);
        case 'get-data': return verifyToken(req, res, () => handleCachedData(req, res));
        case 'status':
            return res.json({ 
                message: "Smsglobe API is running", 
                db: isConnected,
                timestamp: new Date().toISOString()
            });
        default:
            return res.status(404).json({ success: false, error: "Action not found" });
    }
});

// --- 7. LOGIC HANDLERS ---

async function handleLogin(req, res) {
    const { email, password } = req.body;
    try {
        const admin = await Admin.findOne({ email });
        if (!admin || !(await bcrypt.compare(password, admin.password))) {
            return res.status(401).json({ success: false, message: "Invalid credentials" });
        }
        const token = jwt.sign({ id: admin._id, email: admin.email }, JWT_SECRET, { expiresIn: '24h' });
        return res.json({ success: true, token });
    } catch (err) {
        return res.status(500).json({ success: false, message: "Login failed" });
    }
}

async function handleRegister(req, res) {
    const { fullName, email, password } = req.body;
    try {
        const existingAdmin = await Admin.findOne({ email });
        if (existingAdmin) return res.status(400).json({ success: false, message: "Email exists" });
        const hashedPassword = await bcrypt.hash(password, 10);
        const newAdmin = new Admin({ fullName, email, password: hashedPassword });
        await newAdmin.save();
        return res.status(201).json({ success: true, message: "Registered" });
    } catch (err) {
        return res.status(500).json({ success: false, message: "Registration failed" });
    }
}

async function handleCachedData(req, res) {
    const now = Date.now();
    if (localCache.data && (now - localCache.lastFetched < 60000)) {
        return res.json({ source: 'cache', data: localCache.data });
    }
    const freshData = { items: ["ExpressVPN", "NordVPN", "Custom Proxy Node 01"] };
    localCache.data = freshData;
    localCache.lastFetched = now;
    res.json({ source: 'database', data: freshData });
}

// --- 8. STARTUP ---
if (process.env.NODE_ENV !== 'production') {
    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () => console.log(`Running on ${PORT}`));
}

module.exports = app;