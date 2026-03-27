const express = require('express');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const path = require('path');
const { OAuth2Client } = require('google-auth-library');

dotenv.config();
const app = express();

// Initialize Google OAuth Client
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

app.use(cors());
app.use(express.json());

// --- 1. SERVE STATIC FILES ---
app.use(express.static(__dirname, { extensions: ['html'] }));

// This handles everything in the smsadmin folder automatically
app.use('/smsadmin', express.static(path.join(__dirname, 'smsadmin'), {
    extensions: ['html', 'htm']
}));

app.use('/smsuser', express.static(path.join(__dirname, 'smsuser'), {
    extensions: ['html', 'htm']
}));

// --- 2. CONFIGURATION & SCHEMA ---
const JWT_SECRET = process.env.JWT_SECRET;
const RECAPTCHA_SECRET = process.env.RECAPTCHA_SECRET_KEY;

const adminSchema = new mongoose.Schema({
    fullName: { type: String, required: true },
    email: { type: String, required: true, unique: true, index: true },
    password: { type: String, required: true },
}, { timestamps: true });

const Admin = mongoose.models.Admin || mongoose.model('Admin', adminSchema);

const userSchema = new mongoose.Schema({
    fullName: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    balance: { type: Number, default: 0 }
}, { timestamps: true });

const User = mongoose.models.User || mongoose.model('User', userSchema);

const vpnSchema = new mongoose.Schema({
    name: { type: String, required: true },
    provider: String,
    region: String,
    image: String,
    deviceLimit: { type: Number, default: 0 },
    // Array of objects for multiple pricing tiers
    plans: [{
        duration: String, // e.g., "1 Month"
        price: Number     // e.g., 29.99
    }],
    // Credentials & Instructions
    username: String,
    password: { type: String, select: false }, // Good practice: hide pass from general queries
    instructions: String,
    // Legacy support
    price: Number 
}, { timestamps: true });

const VPN = mongoose.models.VPN || mongoose.model('VPN', vpnSchema);

// --- 3. OPTIMIZED MONGOOSE CONNECTION ---
let isConnected = false;
const connectDB = async () => {
    if (isConnected) return;
    try {
        await mongoose.connect(process.env.MONGODB_URI, {
            maxPoolSize: 100, 
            serverSelectionTimeoutMS: 5000,
        });
        isConnected = true;
    } catch (err) {
        console.error("DB Error:", err);
    }
};

// --- 4. HELPERS ---
async function verifyRecaptcha(token) {
    if (!token) return false;
    try {
        const response = await fetch(`https://www.google.com/recaptcha/api/siteverify?secret=${RECAPTCHA_SECRET}&response=${token}`, {
            method: 'POST'
        });
        const data = await response.json();
        return data.success;
    } catch (err) {
        return false;
    }
}

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

// --- 6. API ROUTER (Switch-Case) ---
app.all('/api/:action', async (req, res) => {
    await connectDB();
    const action = req.params.action;

    switch (action) {
        case 'login': return handleLogin(req, res);
        case 'register': return handleRegister(req, res);
        case 'google-login': return handleGoogleLogin(req, res);
        case 'dashboard-stats': return handleDashboardStats(req, res);
        case 'get-users': return handleGetUsers(req, res);
        case 'products': 
            if (req.method === 'GET') return handleGetVPNs(req, res);
            if (req.method === 'POST') return handleAddVPN(req, res);
            if (req.method === 'PATCH') return handleUpdateVPN(req, res);
            if (req.method === 'DELETE') return handleDeleteVPN(req, res);
            break;
        case 'user-register': return handleUserRegister(req, res);
        case 'user-login': return handleUserLogin(req, res);
        case 'status':
            return res.json({ message: "Smsglobe API Active", db: isConnected });
        default:
            return res.status(404).json({ success: false, error: "Action not found" });
    }
});

// --- 7. LOGIC HANDLERS ---

async function handleLogin(req, res) {
    const { email, password, captchaToken } = req.body;

    const isHuman = await verifyRecaptcha(captchaToken);
    if (!isHuman) {
        return res.status(400).json({ success: false, message: "reCAPTCHA failed." });
    }

    try {
        const admin = await Admin.findOne({ email });
        if (!admin || !(await bcrypt.compare(password, admin.password))) {
            return res.status(401).json({ success: false, message: "Invalid credentials" });
        }
        const token = jwt.sign({ id: admin._id, email: admin.email }, JWT_SECRET, { expiresIn: '24h' });
        return res.json({ success: true, token });
    } catch (err) {
        return res.status(500).json({ success: false, message: "Login error" });
    }
}

async function handleGoogleLogin(req, res) {
    const { idToken } = req.body;
    try {
        const ticket = await googleClient.verifyIdToken({
            idToken,
            audience: process.env.GOOGLE_CLIENT_ID
        });
        const { email, name } = ticket.getPayload();

        let admin = await Admin.findOne({ email });
        
        // If admin doesn't exist, create a profile (adjust security if you want to restrict this)
        if (!admin) {
            admin = new Admin({
                fullName: name,
                email: email,
                password: await bcrypt.hash(Math.random().toString(36), 12)
            });
            await admin.save();
        }

        const token = jwt.sign({ id: admin._id, email: admin.email }, JWT_SECRET, { expiresIn: '24h' });
        return res.json({ success: true, token });
    } catch (err) {
        console.error("Google Auth Error:", err);
        return res.status(401).json({ success: false, message: "Google Auth Failed" });
    }
}

async function handleRegister(req, res) {
    const { fullName, email, password, captchaToken } = req.body;
    
    const isHuman = await verifyRecaptcha(captchaToken);
    if (!isHuman) return res.status(400).json({ success: false, message: "reCAPTCHA failed." });

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

async function handleDashboardStats(req, res) {
    try {
        // You'll need to make sure you have a User and Order model defined
        // If they aren't defined in this file, ensure they are imported
        const User = mongoose.models.User || mongoose.model('User', new mongoose.Schema({}, { strict: false }), 'users');
        const Order = mongoose.models.Order || mongoose.model('Order', new mongoose.Schema({}, { strict: false }), 'orders');

        const totalUsers = await User.countDocuments();
        
        // Define Time Ranges
        const now = new Date();
        const startOfDay = new Date(new Date().setHours(0,0,0,0));
        const startOfWeek = new Date(new Date().setDate(now.getDate() - 7));
        const startOfMonth = new Date(now.getFullYear(), now.getMonth(), 1);
        const startOfYear = new Date(now.getFullYear(), 0, 1);

        // Fetch all completed orders (adjust 'status' string to match your DB)
        const orders = await Order.find({ status: 'completed' });

        let stats = {
            totalRevenue: 0,
            daily: 0,
            weekly: 0,
            monthly: 0,
            yearly: 0
        };

        orders.forEach(order => {
            const amt = parseFloat(order.amount || 0);
            const date = new Date(order.createdAt || order.timestamp);

            stats.totalRevenue += amt;
            if (date >= startOfDay) stats.daily += amt;
            if (date >= startOfWeek) stats.weekly += amt;
            if (date >= startOfMonth) stats.monthly += amt;
            if (date >= startOfYear) stats.yearly += amt;
        });

        return res.json({ success: true, totalUsers, ...stats });
    } catch (err) {
        console.error("Dashboard Stats Error:", err);
        return res.status(500).json({ success: false, message: "Failed to fetch stats" });
    }
}

async function handleGetUsers(req, res) {
    try {
        // We'll define the User model dynamically if not already present
        const User = mongoose.models.User || mongoose.model('User', new mongoose.Schema({}, { strict: false }), 'users');
        
        // Fetch all users, sorted by newest first
        const users = await User.find({}).sort({ createdAt: -1 });

        return res.json({ 
            success: true, 
            users: users.map(u => ({
                fullName: u.fullName,
                email: u.email,
                balance: u.balance || 0, // Ensure balance defaults to 0
                createdAt: u.createdAt
            }))
        });
    } catch (err) {
        return res.status(500).json({ success: false, message: "Database Error" });
    }
}
// --- Updated Handlers for VPN Management ---

async function handleGetVPNs(req, res) {
    try {
        const vpns = await VPN.find({}).sort({ createdAt: -1 });
        // Keeping 'products' key for frontend compatibility
        res.json({ success: true, products: vpns }); 
    } catch (err) {
        res.status(500).json({ success: false, message: "Fetch failed" });
    }
}

async function handleAddVPN(req, res) {
    try {
        const data = req.body;

        // Ensure plans are formatted correctly (numbers are stored as numbers)
        if (data.plans && Array.isArray(data.plans)) {
            data.plans = data.plans.map(p => ({
                duration: p.duration,
                price: parseFloat(p.price) || 0
            }));
        }

        const newVPN = new VPN({
            ...data,
            deviceLimit: parseInt(data.deviceLimit) || 0,
            // Fallback for legacy price field if your schema still requires it
            price: data.plans && data.plans.length > 0 ? parseFloat(data.plans[0].price) : 0
        });

        await newVPN.save();
        res.json({ success: true, message: "VPN Node Synced Successfully" });
    } catch (err) {
        console.error("Add VPN Error:", err);
        res.status(500).json({ success: false, message: "Upload failed" });
    }
}

async function handleUpdateVPN(req, res) {
    try {
        const { vpnId, ...updateData } = req.body;
        
        // Clean up data before update
        if (updateData.plans && Array.isArray(updateData.plans)) {
            updateData.plans = updateData.plans.map(p => ({
                duration: p.duration,
                price: parseFloat(p.price) || 0
            }));
            
            // Sync the main price field with the first plan for legacy support
            if (updateData.plans.length > 0) {
                updateData.price = updateData.plans[0].price;
            }
        }

        if (updateData.deviceLimit) {
            updateData.deviceLimit = parseInt(updateData.deviceLimit);
        }
        
        const updated = await VPN.findByIdAndUpdate(vpnId, updateData, { new: true });
        
        if (!updated) {
            return res.status(404).json({ success: false, message: "VPN node not found" });
        }

        res.json({ success: true, message: "VPN Configuration Updated" });
    } catch (err) {
        console.error("Update VPN Error:", err);
        res.status(500).json({ success: false, message: "Update failed" });
    }
}

async function handleDeleteVPN(req, res) {
    try {
        const { id } = req.query;
        if (!id) return res.status(400).json({ success: false, message: "ID is required" });
        
        await VPN.findByIdAndDelete(id);
        res.json({ success: true, message: "VPN Node Deleted" });
    } catch (err) {
        res.status(500).json({ success: false, message: "Delete failed" });
    }
}

async function handleUserLogin(req, res) {
    const { email, password, captchaToken } = req.body;

    const isHuman = await verifyRecaptcha(captchaToken);
    if (!isHuman) {
        return res.status(400).json({ success: false, message: "reCAPTCHA failed." });
    }

    try {
        // Find user by email
        const user = await User.findOne({ email });
        
        // Check user existence and compare password
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ success: false, message: "Invalid email or password" });
        }

        // Generate JWT Token
        const token = jwt.sign(
            { id: user._id, email: user.email, type: 'user' }, 
            JWT_SECRET, 
            { expiresIn: '24h' }
        );

        return res.json({ success: true, token });
    } catch (err) {
        console.error("User Login Error:", err);
        return res.status(500).json({ success: false, message: "Server error during login" });
    }
}

async function handleUserRegister(req, res) {
    const { fullName, email, password, captchaToken } = req.body;

    const isHuman = await verifyRecaptcha(captchaToken);
    if (!isHuman) return res.status(400).json({ success: false, message: "reCAPTCHA failed." });

    try {
        const existingUser = await User.findOne({ email });
        if (existingUser) return res.status(400).json({ success: false, message: "User already exists." });

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ fullName, email, password: hashedPassword });
        
        await newUser.save();
        return res.status(201).json({ success: true, message: "User created" });
    } catch (err) {
        return res.status(500).json({ success: false, message: "Server error" });
    }
}

// --- 8. STARTUP ---
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

if (process.env.NODE_ENV !== 'production') {
    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () => console.log(`Dev Server: http://localhost:${PORT}`));
}

module.exports = app;