const express = require('express');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs'); // Added for secure password hashing

dotenv.config();
const app = express();

app.use(cors());
app.use(express.json());

// --- 1. CONFIGURATION & SCHEMA ---
const JWT_SECRET = process.env.JWT_SECRET;

const adminSchema = new mongoose.Schema({
    fullName: { type: String, required: true },
    email: { type: String, required: true, unique: true, index: true }, // Indexing for 1M user scale
    password: { type: String, required: true },
}, { timestamps: true });

// Prevent model overwrite during hot-reloads
const Admin = mongoose.models.Admin || mongoose.model('Admin', adminSchema);

// --- 2. OPTIMIZED MONGOOSE CONNECTION ---
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

// --- 3. CACHING ---
let localCache = {
    data: null,
    lastFetched: 0
};

// --- 4. MIDDLEWARE ---
const verifyToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(403).json({ success: false, error: "No token provided" });

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        return res.status(401).json({ success: false, error: "Unauthorized: Invalid or expired token" });
    }
};

// --- 5. CENTRAL CONTROLLER ---
app.all('/api/:action', async (req, res) => {
    await connectDB();
    const action = req.params.action;

    switch (action) {
        case 'login':
            return handleLogin(req, res);
        
        case 'register':
            return handleRegister(req, res);

        case 'get-data':
            // Verify token before allowing access to data
            return verifyToken(req, res, () => handleCachedData(req, res));

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

// --- 6. LOGIC HANDLERS ---

async function handleLogin(req, res) {
    const { email, password } = req.body;
    
    try {
        const admin = await Admin.findOne({ email });
        if (!admin) {
            return res.status(401).json({ success: false, message: "Invalid email or password" });
        }

        // Compare incoming plain password with hashed DB password
        const isMatch = await bcrypt.compare(password, admin.password);
        if (!isMatch) {
            return res.status(401).json({ success: false, message: "Invalid email or password" });
        }

        const token = jwt.sign(
            { id: admin._id, email: admin.email, role: 'admin' }, 
            JWT_SECRET, 
            { expiresIn: '24h' }
        );

        return res.json({ 
            success: true, 
            token: token,
            message: "Authentication successful" 
        });
    } catch (err) {
        return res.status(500).json({ success: false, message: "Login failed" });
    }
}

async function handleRegister(req, res) {
    const { fullName, email, password } = req.body;

    try {
        const existingAdmin = await Admin.findOne({ email });
        if (existingAdmin) {
            return res.status(400).json({ success: false, message: "Email already exists" });
        }

        // Hash password before saving
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const newAdmin = new Admin({
            fullName,
            email,
            password: hashedPassword
        });

        await newAdmin.save();
        return res.status(201).json({ success: true, message: "Admin registered successfully" });
    } catch (err) {
        return res.status(500).json({ success: false, message: "Registration failed" });
    }
}

async function handleCachedData(req, res) {
    const now = Date.now();
    if (localCache.data && (now - localCache.lastFetched < 60000)) {
        return res.json({ source: 'cache', data: localCache.data });
    }

    // Replace this with your actual DB query for VPNs/Proxies
    const freshData = { items: ["ExpressVPN", "NordVPN", "Custom Proxy Node 01"] };
    localCache.data = freshData;
    localCache.lastFetched = now;

    res.json({ source: 'database', data: freshData });
}

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

module.exports = app;