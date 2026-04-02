const express = require('express');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const path = require('path');
const { OAuth2Client } = require('google-auth-library');
const nodemailer = require('nodemailer');
const axios = require('axios');


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
}, { timestamps: true });

const User = mongoose.models.User || mongoose.model('User', userSchema);

const vpnSchema = new mongoose.Schema({
    name: { type: String, required: true },
    provider: String,
    region: String,
    image: String, // URL for the node image
    stock: { type: Number, default: 0 }, // Added stock field
    deviceLimit: { type: Number, default: 0 },
    plans: [{
        duration: String, 
        price: Number     
    }],
    username: String,
    password: { type: String, select: false },
    instructions: String,
    price: Number 
}, { timestamps: true });

const VPN = mongoose.models.VPN || mongoose.model('VPN', vpnSchema);

const ProxySchema = new mongoose.Schema({
    name: { type: String, required: true },
    category: { type: String, default: 'Standard' },
    imageUrl: { type: String },
    activationCode: { type: String },
    instructions: { type: String },
    stock: { type: Number, default: 0 }, // Added Stock field
    plans: [{
        ip_count: { type: Number, required: true },
        price: { type: Number, required: true }
    }],
    createdAt: { type: Date, default: Date.now }
});

const Proxy = mongoose.models.Proxy || mongoose.model('Proxy', ProxySchema);

const esimRefillSchema = new mongoose.Schema({
    nodeName: { type: String, required: true },    // Changed from carrierName
    targetNumber: { type: String, required: true }, // Changed from mobileNumber
    planName: { type: String, required: true },    // Changed from planAmount
    userEmail: { type: String, required: true, index: true },
    fullName: { type: String },                    // Added based on your DB output
    paymentReference: { type: String, unique: true }, // Changed from refId to match your DB
    confirmationNumber: { type: String }, 
    status: { 
        type: String, 
        enum: ['pending', 'processing', 'completed', 'failed', 'successful', 'Completed'], // Added 'Completed' with capital C
        default: 'pending' 
    },    
    adminUpdatedBy: { type: String } 
}, { timestamps: true });

const EsimRefill = mongoose.models.EsimRefill || mongoose.model('EsimRefill', esimRefillSchema);

const esimActivationSchema = new mongoose.Schema({
    userEmail: { type: String, required: true, index: true },
    email: { type: String, required: true,   lowercase: true,  trim: true}, 
    fullName: { type: String },
    nodeName: { type: String, required: true }, // The carrier/provider name
    planName: { type: String, required: true }, // e.g., "10GB - 30 Days"
    confirmationNumber: { type: String },       // Added for tracking activation status
    amount: { type: Number, required: true },
    paymentReference: { type: String, unique: true },
    status: { 
        type: String, 
        enum: ['pending', 'processing', 'completed', 'failed', 'successful'], 
        default: 'pending' 
    },
    adminUpdatedBy: { type: String }
}, { timestamps: true });

const EsimActivation = mongoose.models.EsimActivation || mongoose.model('EsimActivation', esimActivationSchema);

const rdpSchema = new mongoose.Schema({
    name: { type: String, required: true },
    category: { type: String, enum: ['Windows', 'Linux', 'Server', 'All RDP'], default: 'Windows' },
    ram: { type: String, required: true }, 
    cpu: { type: String, required: true }, 
    storage: { type: String, required: true }, 
    network: { type: String, default: "100Mbps" },
    // Optional Customization
    extraCPU: { type: Number, default: 0 },
    extraStorage: { type: Number, default: 0 },
    
    os: { type: String, default: "Windows Server 2022/2025" },
    price: { type: Number, required: true },
    isInstant: { type: Boolean, default: true },
    instructions: { type: String, default: "General setup instructions will be provided after purchase." },
    adminUpdatedBy: String
}, { timestamps: true });

const RDP = mongoose.models.RDP || mongoose.model('RDP', rdpSchema);

const rentedNumberSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    
    // --- Identification ---
    externalId: { type: String, required: true, unique: true }, // Textverified's Verification ID or Rental ID
    phoneNumber: { type: String, required: true },
    
    // --- Mode ---
    activationType: { 
        type: String, 
        enum: ['activation', 'rent'], 
        required: true 
    },

    // --- Service Details ---
    service: { 
        type: String, 
        required: true, 
        // Removed enum to allow dynamic Textverified target names
    },
    serviceName: { type: String }, 
    targetId: { type: String }, // Store Textverified's internal Target ID

    // --- Location ---
    country: { 
        name: String, 
        code: String, 
        prefix: String 
    },

    // --- Financials ---
    price: { type: Number, required: true },
    currency: { type: String, default: 'NGN' },

    // --- Status ---
    status: { 
        type: String, 
        enum: ['pending', 'active', 'completed', 'expired', 'canceled'], 
        default: 'pending' 
    },

    // --- SMS Data ---
    otpReceived: [{ 
        code: String, 
        sender: String, 
        fullText: String, 
        timestamp: { type: Date, default: Date.now } 
    }],

    // --- Timing ---
    expiresAt: { 
        type: Date, 
        required: true, 
        // Default to 15 mins for activations, can be overridden for rentals
        default: () => new Date(Date.now() + 15 * 60000) 
    }
}, { timestamps: true });

// Index for performance and auto-expiry cleanup
rentedNumberSchema.index({ user: 1, createdAt: -1 });
rentedNumberSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 }); 

const RentedNumber = mongoose.models.RentedNumber || mongoose.model('RentedNumber', rentedNumberSchema);

const orderSchema = new mongoose.Schema({
    userEmail: { type: String, required: true, index: true },
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    fullName: { type: String },         
    productType: { 
        type: String, 
        enum: ['VPN', 'Proxy', 'eSIM', 'eSIM_Refill', 'eSIM_Activation', 'RDP'], 
        required: true 
    },
    planName: { type: String }, 
    nodeName: { type: String }, 
    productImage: { type: String },
    targetNumber: { type: String }, 
    confirmationNumber: String,
    amount: { type: Number, required: true },
    currency: { type: String, default: 'USD' }, 
    paymentGateway: { type: String }, 
    status: { 
        type: String, 
        enum: ['pending', 'successful', 'failed', 'completed'], 
        default: 'pending' 
    }, 
   metadata: {
        address: String,
        zip: String,
        firstName: String,
        lastName: String,
        email: String,
        extraCPU: { type: Number, default: 0 },
        extraStorage: { type: Number, default: 0 },
        osChoice: String
    },
    paymentReference: { type: String, unique: true },
    activationCode: String, 
    vpnCredentials: {
        username: String,
        password: { type: String }
    },
    rdpDetails: {
        os: String,
        specs: String
    }
}, { timestamps: true });

orderSchema.index({ createdAt: -1 });

const Order = mongoose.models.Order || mongoose.model('Order', new mongoose.Schema({}, { strict: false }), 'orders');

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
        // Google expects 'secret' and 'response' in the body for POST requests
        const params = new URLSearchParams();
        params.append('secret', process.env.RECAPTCHA_SECRET_KEY);
        params.append('response', token);

        const response = await fetch('https://www.google.com/recaptcha/api/siteverify', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: params.toString()
        });

        const data = await response.json();
        if (!data.success) {
            console.error("reCAPTCHA Error Codes:", data['error-codes']);
        }

        return data.success;
    } catch (err) {
        console.error("reCAPTCHA Network/System Error:", err);
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

app.all('/api/:action', async (req, res) => {
    await connectDB();
    const action = (req.params.action || '').toLowerCase().trim();
    console.log("Incoming Action:", action, "Method:", req.method);

    switch (action) {
        case 'login': return handleLogin(req, res);
        case 'register': return handleRegister(req, res);
        case 'google-login': return handleGoogleLogin(req, res);
        case 'dashboard-stats': return handleDashboardStats(req, res);
        case 'get-users': return handleGetUsers(req, res);
        case 'manage-user': return handleManageUser(req, res);
        case 'products': 
            if (req.method === 'GET') return handleGetVPNs(req, res);
            if (req.method === 'POST') return handleAddVPN(req, res);
            if (req.method === 'PATCH') return handleUpdateVPN(req, res);
            if (req.method === 'DELETE') return handleDeleteVPN(req, res);
            break;
        case 'user-register': return handleUserRegister(req, res);
        case 'user-login': return handleUserLogin(req, res);
        case 'user-profile': return handleGetUserProfile(req, res);
        case 'user-messages': return handleGetUserMessages(req, res);
        case 'purchase-vpn': return handlePurchaseVPN(req, res);
        case 'initiate-payment': return handleInitiatePayment(req, res);
        case 'verify-payment': return handleVerifyPayment(req, res);
        case 'proxies': 
            if (req.method === 'GET') return handleGetProxies(req, res);
            if (req.method === 'POST') return handleAddProxy(req, res);
            if (req.method === 'PATCH') return handleUpdateProxy(req, res);
            if (req.method === 'DELETE') return handleDeleteProxy(req, res);
            break;
        case 'transactions': return handleAllTransactions(req, res);
        case 'esim-refill': 
            if (req.method === 'POST') return handleEsimRefill(req, res);
            break;
        case 'create-esim-order': return handleCreateEsimOrder(req, res);
        case 'esim-refills': return getEsimRefills(req, res);
        case 'update-esim-status':
            return handleAdminEsimUpdate(req, res);
        case 'create-esim-order-activation': return handleCreateEsimActivation(req, res);
      case 'esim-activation': 
        case 'esim-activations': 
        if (req.method === 'GET') return handleGetEsimActivations(req, res); 
        break;
    case 'esim-activation-complete': 
    case 'update-esim-activation': 
    if (req.method === 'POST' || req.method === 'PATCH') {
        return handleAdminEsimActivationUpdate(req, res);
    }
    break;
    case 'rdps': 
    if (req.method === 'GET') return handleGetRDPs(req, res); // You'll need to create this
    if (req.method === 'POST') return handleAddRDP(req, res); // You'll need to create this
    if (req.method === 'PATCH') return handleCompleteRDPOrder(req, res);
    if (req.method === 'DELETE') return handleDeleteRDP(req, res);
    break;
    case 'rdp-requests': // This matches the fetch URL in your HTML file
    if (req.method === 'GET') return handleGetRdpRequests(req, res);
    break;
     case 'rdp-request-complete': // This matches the fetch URL in your HTML file
    if (req.method === 'POST') return handleCompleteRDPOrder(req, res);
    break;
        case 'tellabot/numbers':
        case 'get-numbers': 
            return handleGetNumbers(req, res); 

        case 'rentals/activate':
        case 'purchase/process':
            return handleActivatePurchase(req, res);
        case 'status':
            return res.json({ message: "Smsglobe API Active", db: isConnected });
            
        default:
            return res.status(404).json({ 
                success: false, 
                error: `Action '${action}' not found on this server.` 
            });
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

// --- Updated Google Login Handler ---
async function handleGoogleLogin(req, res) {
    const { idToken, loginType } = req.body; // 'admin' or 'user'
    
    try {
        const ticket = await googleClient.verifyIdToken({
            idToken,
            audience: process.env.GOOGLE_CLIENT_ID
        });
        const { email, name } = ticket.getPayload();

        let Model = (loginType === 'admin') ? Admin : User;
        let targetAccount = await Model.findOne({ email: email.toLowerCase() });
        
        if (!targetAccount) {
            // Create a new account if it doesn't exist
            targetAccount = new Model({
                fullName: name,
                email: email.toLowerCase(),
                // Secure random password for social login users
                password: await bcrypt.hash(Math.random().toString(36), 12)
                // Balance logic removed from here
            });
            await targetAccount.save();
        }

        // Generate Token
        const token = jwt.sign(
            { id: targetAccount._id, email: targetAccount.email, role: loginType }, 
            JWT_SECRET, 
            { expiresIn: '24h' }
        );

        return res.json({ 
            success: true, 
            token,
            user: { name: targetAccount.fullName, email: targetAccount.email }
        });
        
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
        const User = mongoose.models.User || mongoose.model('User');
        const Order = mongoose.models.Order || mongoose.model('Order');

        const totalUsers = await User.countDocuments();
        const RATE = parseFloat(process.env.USD_TO_NGN_RATE) || 1650; 

        const now = new Date();
        const startOfDay = new Date(); startOfDay.setHours(0,0,0,0);
        const startOfWeek = new Date(); startOfWeek.setDate(now.getDate() - 7);
        const startOfMonth = new Date(now.getFullYear(), now.getMonth(), 1);
        const startOfYear = new Date(now.getFullYear(), 0, 1);

        const orders = await Order.find({ 
            status: { $in: ['successful', 'completed'] } 
        });

        // Initialize separate counters
        let usdStats = { totalRevenue: 0, daily: 0, weekly: 0, monthly: 0, yearly: 0 };
        let ngnStats = { totalRevenue: 0, daily: 0, weekly: 0, monthly: 0, yearly: 0 };

        orders.forEach(order => {
            const rawAmount = parseFloat(order.amount || 0);
            const date = new Date(order.createdAt || now);
            
            let valUSD = 0;
            let valNGN = 0;

            // Check the actual currency saved in the database
            if (order.currency === 'NGN') {
                valNGN = rawAmount;
                valUSD = rawAmount / RATE; // Convert NGN back to USD for stats
            } else {
                valUSD = rawAmount;
                valNGN = rawAmount * RATE; // Convert USD to NGN for stats
            }

            // Update USD Stats
            usdStats.totalRevenue += valUSD;
            if (date >= startOfDay) usdStats.daily += valUSD;
            if (date >= startOfWeek) usdStats.weekly += valUSD;
            if (date >= startOfMonth) usdStats.monthly += valUSD;
            if (date >= startOfYear) usdStats.yearly += valUSD;

            // Update NGN Stats
            ngnStats.totalRevenue += valNGN;
            if (date >= startOfDay) ngnStats.daily += valNGN;
            if (date >= startOfWeek) ngnStats.weekly += valNGN;
            if (date >= startOfMonth) ngnStats.monthly += valNGN;
            if (date >= startOfYear) ngnStats.yearly += valNGN;
        });

        // Fetch 5 most recent orders for the "Recent Activity" table
        const recentOrders = await Order.find({ status: 'successful' })
            .sort({ createdAt: -1 })
            .limit(5);

        return res.json({ 
            success: true, 
            totalUsers,
            usd: usdStats,
            ngn: ngnStats,
            recentOrders // Send this so the table updates too
        });
    } catch (err) {
        console.error("Stats Error:", err);
        return res.status(500).json({ success: false, message: "Internal Server Error" });
    }
}

// GET /api/admin/transactions
async function handleAllTransactions(req, res) {
    try {
        const Order = mongoose.models.Order || mongoose.model('Order', new mongoose.Schema({}, { strict: false }), 'orders');
        
        // Fetch all successful orders, sorted by newest first
        const transactions = await Order.find({ 
            status: { $in: ['successful', 'completed', 'paid'] } 
        }).sort({ createdAt: -1 });

        return res.json({ 
            success: true, 
            transactions: transactions.map(t => ({
                id: t._id,
                email: t.userEmail || 'N/A',
                product: t.productType || t.planName || 'Service',
                details: t.nodeName || t.location || 'Standard Plan',
                amount: t.amount || 0,
                // Ensure currency defaults to USD if not specified, but captures NGN if present
                currency: t.currency ? t.currency.toUpperCase() : 'USD', 
                date: t.createdAt || t.timestamp
            }))
        });
    } catch (err) {
        console.error("Transaction Fetch Error:", err);
        return res.status(500).json({ success: false });
    }
}

async function handleGetUsers(req, res) {
    try {
        const User = mongoose.models.User || mongoose.model('User', new mongoose.Schema({}, { strict: false }), 'users');
        const users = await User.find({}).sort({ createdAt: -1 });

        return res.json({ 
            success: true, 
            users: users.map(u => ({
                _id: u._id, // Added ID for actions
                fullName: u.fullName,
                email: u.email,
                status: u.status || 'active', // Added status
                createdAt: u.createdAt
            }))
        });
    } catch (err) {
        return res.status(500).json({ success: false, message: "Database Error" });
    }
}
async function handleManageUser(req, res) {
    const { action, userId } = req.body;
    try {
        const User = mongoose.models.User || mongoose.model('User');

        if (action === 'delete') {
            await User.findByIdAndDelete(userId);
            return res.json({ success: true, message: "User deleted successfully." });
        }

        const newStatus = action === 'suspend' ? 'suspended' : 'active';
        await User.findByIdAndUpdate(userId, { status: newStatus });
        
        return res.json({ success: true, message: `User is now ${newStatus}.` });
    } catch (err) {
        return res.status(500).json({ success: false, message: "Action failed." });
    }
}
async function handleGetVPNs(req, res) {
    try {
        // Fetch all VPNs, including the hidden password field for the admin to see/edit
        const vpns = await VPN.find({}).sort({ createdAt: -1 }).select('+password');
        res.json({ success: true, products: vpns }); 
    } catch (err) {
        res.status(500).json({ success: false, message: "Fetch failed" });
    }
}

async function handleAddVPN(req, res) {
    try {
        const data = req.body;

        // 1. Format plans and ensure prices are numbers
        if (data.plans && Array.isArray(data.plans)) {
            data.plans = data.plans.map(p => ({
                duration: p.duration,
                price: parseFloat(p.price) || 0
            }));
        }

        const newVPN = new VPN({
            ...data,
            // 2. Ensure Stock and Device Limit are stored as Integers
            stock: parseInt(data.stock) || 0, 
            deviceLimit: parseInt(data.deviceLimit) || 0,
            // Sync legacy price field with the first plan
            price: data.plans && data.plans.length > 0 ? parseFloat(data.plans[0].price) : 0
        });

        await newVPN.save();
        res.json({ success: true, message: "VPN Node & Stock Synced Successfully" });
    } catch (err) {
        console.error("Add VPN Error:", err);
        res.status(500).json({ success: false, message: "Upload failed" });
    }
}

async function handleUpdateVPN(req, res) {
    try {
        const { vpnId, ...updateData } = req.body;
        
        // 1. Clean up plans data
        if (updateData.plans && Array.isArray(updateData.plans)) {
            updateData.plans = updateData.plans.map(p => ({
                duration: p.duration,
                price: parseFloat(p.price) || 0
            }));
            
            if (updateData.plans.length > 0) {
                updateData.price = updateData.plans[0].price;
            }
        }

        // 2. Parse Numeric Fields
        if (updateData.stock !== undefined) {
            updateData.stock = parseInt(updateData.stock) || 0;
        }

        if (updateData.deviceLimit !== undefined) {
            updateData.deviceLimit = parseInt(updateData.deviceLimit) || 0;
        }
        
        const updated = await VPN.findByIdAndUpdate(vpnId, updateData, { new: true });
        
        if (!updated) {
            return res.status(404).json({ success: false, message: "VPN node not found" });
        }

        res.json({ success: true, message: "VPN Configuration & Stock Updated" });
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
// --- 1. User Login Handler ---
async function handleUserLogin(req, res) {
    const { email, password, captchaToken } = req.body;

    if (!captchaToken) {
        return res.status(400).json({ success: false, message: "reCAPTCHA token missing." });
    }

    const isHuman = await verifyRecaptcha(captchaToken);
    if (!isHuman) {
        return res.status(400).json({ success: false, message: "Security verification failed. Please try again." });
    }

    try {
        const user = await User.findOne({ email: email.toLowerCase().trim() });
        
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ success: false, message: "Invalid email or password." });
        }

        const token = jwt.sign(
            { id: user._id, email: user.email, type: 'user' }, 
            JWT_SECRET, 
            { expiresIn: '24h' }
        );

        return res.json({ 
            success: true, 
            token,
            user: { name: user.fullName, email: user.email } 
        });
    } catch (err) {
        console.error("Login Error:", err);
        return res.status(500).json({ success: false, message: "An internal server error occurred." });
    }
}

// --- 2. User Registration Handler ---
async function handleUserRegister(req, res) {
    const { fullName, email, password, captchaToken } = req.body;

    if (!captchaToken) {
        return res.status(400).json({ success: false, message: "reCAPTCHA token missing." });
    }

    const isHuman = await verifyRecaptcha(captchaToken);
    if (!isHuman) {
        return res.status(400).json({ success: false, message: "reCAPTCHA verification failed." });
    }

    try {
        const normalizedEmail = email.toLowerCase().trim();

        const existingUser = await User.findOne({ email: normalizedEmail });
        if (existingUser) {
            return res.status(400).json({ success: false, message: "This email is already registered." });
        }

        const hashedPassword = await bcrypt.hash(password, 12);
        
        const newUser = new User({ 
            fullName: fullName.trim(), 
            email: normalizedEmail, 
            password: hashedPassword
            // balance: 0 <--- REMOVED
        });
        
        await newUser.save();
        
        return res.status(201).json({ 
            success: true, 
            message: "Account created successfully! You can now log in." 
        });
    } catch (err) {
        console.error("Registration Error:", err);
        return res.status(500).json({ success: false, message: "Failed to create account." });
    }
}

// Fetch profile for the logged-in user
async function handleGetUserProfile(req, res) {
    // 1. Manually verify token since this is inside the general API router
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await User.findById(decoded.id).select('-password');
        
        if (!user) return res.status(404).json({ success: false, message: "User not found" });
        
        return res.json({ 
            success: true, 
            full_name: user.fullName, 
            email: user.email, 
            balance: user.balance 
        });
    } catch (err) {
        return res.status(401).json({ success: false, message: "Unauthorized" });
    }
}

// Fetch SMS messages for the logged-in user
async function handleGetUserMessages(req, res) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        
        // Ensure you have a Message model defined
        const Message = mongoose.models.Message || mongoose.model('Message', new mongoose.Schema({
            userId: mongoose.Schema.Types.ObjectId,
            service: String,
            number: String,
            code: String,
            createdAt: { type: Date, default: Date.now }
        }), 'messages');

        const messages = await Message.find({ userId: decoded.id }).sort({ createdAt: -1 }).limit(10);
        return res.json(messages); 
    } catch (err) {
        return res.status(401).json({ success: false, message: "Unauthorized" });
    }
}

async function handlePurchaseVPN(req, res) {
    const { vpnId, planIndex, currency } = req.body; // Added currency to body
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        
        // 1. Fetch VPN and include password
        const vpn = await VPN.findById(vpnId).select('+password'); 

        // 2. Validate VPN and Plan existence
        if (!vpn || !vpn.plans[planIndex]) {
            return res.status(404).json({ success: false, message: "VPN Node or Plan not found." });
        }

        // 3. Check Stock availability
        if (vpn.stock <= 0) {
            return res.status(400).json({ success: false, message: "This VPN node is currently out of stock." });
        }

        const selectedPlan = vpn.plans[planIndex];

        // --- NEW: RECORD THE TRANSACTION IN DATABASE ---
        // This is what fills the empty "orders" collection in your screenshot
        const Order = mongoose.models.Order || mongoose.model('Order'); // Ensure Order model is loaded
        
        const newOrder = new Order({
            userEmail: decoded.email, // Taking email from the verified JWT token
            productType: 'VPN',
            planName: selectedPlan.duration,
            nodeName: vpn.name,
            amount: selectedPlan.price,
            currency: currency || 'USD', // Captured from frontend (USD or NGN)
            status: 'successful',
            vpnCredentials: {
                username: vpn.username,
                password: vpn.password
            }
        });

        await newOrder.save(); 
        // -----------------------------------------------

        // 4. Update Inventory
        vpn.stock -= 1;
        await vpn.save();

        // 5. Return Credentials
        return res.json({ 
            success: true, 
            message: "Access granted successfully!",
            orderId: newOrder._id, // Helpful for frontend reference
            credentials: {
                username: vpn.username,
                password: vpn.password,
                deviceLimit: vpn.deviceLimit,
                instructions: vpn.instructions
            },
            remainingStock: vpn.stock
        });
        
    } catch (err) {
        console.error("VPN Access Error:", err);
        return res.status(401).json({ success: false, message: "Unauthorized or Session Expired" });
    }
}

async function handleInitiatePayment(req, res) {
    const { vpnId, proxyId, rdpId, carrierName, mobileNumber, planAmount, planIndex, metadata, planName } = req.body;
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    const USD_TO_NGN_RATE = 1650; 

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await User.findById(decoded.id);
        if (!user) return res.status(404).json({ success: false, message: "User not found" });
        
        let item;
        let itemType;
        let title;
        let amountInUSD = 0;
        let finalAmountNGN = 0;
        let redirectUrl = "https://smsglobe.vercel.app/smsuser/user_dashboard.html";

        if (vpnId) {
            item = await VPN.findById(vpnId);
            if (!item || !item.plans[planIndex]) return res.status(404).json({ success: false, message: "VPN Plan not found" });
            itemType = "VPN";
            title = "SMSGlobe VPN";
            amountInUSD = item.plans[planIndex].price;
            finalAmountNGN = Math.round(amountInUSD * USD_TO_NGN_RATE);
            redirectUrl = "https://smsglobe.vercel.app/smsuser/user_vpn.html";
        } 
        else if (proxyId) {
            item = await Proxy.findById(proxyId);
            if (!item || !item.plans[planIndex]) return res.status(404).json({ success: false, message: "Proxy Plan not found" });
            itemType = "Proxy";
            title = "SMSGlobe Proxy";
            amountInUSD = item.plans[planIndex].price;
            finalAmountNGN = Math.round(amountInUSD * USD_TO_NGN_RATE);
            redirectUrl = "https://smsglobe.vercel.app/smsuser/user_proxy.html";
        } 
        else if (carrierName) {
            itemType = metadata ? "eSIM_Activation" : "eSIM";
            title = metadata ? `eSIM Activation: ${carrierName}` : `eSIM Refill: ${carrierName}`;
            amountInUSD = parseFloat(planAmount.replace(/[$,]/g, ''));
            finalAmountNGN = Math.round(amountInUSD * USD_TO_NGN_RATE);
            redirectUrl = metadata 
                ? "https://smsglobe.vercel.app/smsuser/esim_activation.html" 
                : "https://smsglobe.vercel.app/smsuser/esim_refill.html";
        } 
        else if (rdpId) {
            itemType = "RDP";
            redirectUrl = "https://smsglobe.vercel.app/smsuser/user_rdp.html";

            const extraCPU = metadata?.extraCPU || 0;
            const extraStorage = metadata?.extraStorage || 0;
            const addonTotal = (extraCPU * 5000) + (extraStorage * 200);

            if (typeof rdpId === 'string' && rdpId.startsWith('tier')) {
                const tierPrices = {
                    tier1: 45000, tier2: 55000, tier3: 65000,
                    tier4: 80000, tier5: 90000, tier6: 130000
                };

                const basePriceNGN = tierPrices[rdpId] || 45000;
                title = `SMSGlobe RDP: ${planName || rdpId.toUpperCase()}`;
                finalAmountNGN = basePriceNGN + addonTotal;
            } 
            else {
                try {
                    item = await RDP.findById(rdpId);
                    if (!item) return res.status(404).json({ success: false, message: "RDP Plan not found" });
                    
                    title = `SMSGlobe RDP: ${item.name}`;
                    finalAmountNGN = item.price + addonTotal;
                } catch (err) {
                    return res.status(400).json({ success: false, message: "Invalid RDP ID provided" });
                }
            }
        } 
        else {
            return res.status(400).json({ success: false, message: "No product specified" });
        }

        const tx_ref = `SMS-${itemType}-${Date.now()}-${decoded.id.slice(-4)}`;
        const activationEmail = metadata?.email || null;

        const response = await fetch("https://api.flutterwave.com/v3/payments", {
            method: "POST",
            headers: {
                Authorization: `Bearer ${process.env.FLW_SECRET_KEY}`,
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                tx_ref: tx_ref,
                amount: finalAmountNGN,
                currency: "NGN",
                redirect_url: redirectUrl,
                customer: {
                    email: user.email,
                    name: user.fullName,
                },
                meta: {
                    userId: decoded.id,
                    email: activationEmail,
                    productType: itemType,
                    productId: rdpId || vpnId || proxyId || carrierName, 
                    planIndex: planIndex,
                    extraCPU: metadata?.extraCPU || 0,
                    extraStorage: metadata?.extraStorage || 0,
                    osChoice: metadata?.osChoice || null,
                    mobileNumber: mobileNumber || null
                },
                customizations: {
                    title: title,
                    description: itemType === "RDP" 
                        ? `${planName || title} (${metadata?.osChoice || 'Windows'})` 
                        : itemType.includes("eSIM")
                        ? `Refill/Activation for ${mobileNumber || carrierName}`
                        : `${item?.name || title} ($${amountInUSD} USD)`,
                    logo: "https://imgur.com/8YeZgfx.png"
                },
            }),
        });

        const data = await response.json();
        if (data.status === "success") {
            return res.json({ success: true, link: data.data.link });
        } else {
            console.error("Flutterwave API Error:", data);
            return res.status(500).json({ success: false, message: "Flutterwave Error" });
        }
    } catch (err) {
        console.error("Initiate Payment Error:", err);
        const statusCode = err.name === 'JsonWebTokenError' ? 401 : 500;
        return res.status(statusCode).json({ 
            success: false, 
            message: err.name === 'JsonWebTokenError' ? "Session Expired" : "Internal Server Error" 
        });
    }
}

async function handleVerifyPayment(req, res) {
    const { transactionId } = req.body;

    try {
        // 1. Verify with Flutterwave
        const response = await fetch(`https://api.flutterwave.com/v3/transactions/${transactionId}/verify`, {
            method: "GET",
            headers: { Authorization: `Bearer ${process.env.FLW_SECRET_KEY}` },
        });

        const data = await response.json();

        // Debugging: Log the verification data
        console.log("Flutterwave Verification Response:", JSON.stringify(data, null, 2));

        if (data.status === "success" && data.data.status === "successful") {
            const meta = data.data.meta || {};
            const paymentRef = data.data.tx_ref;

            // --- CRITICAL: DUPLICATE CHECK (PREVENTS E11000 ERROR) ---
            // If the user refreshes the page, this prevents creating the same order twice.
            const existingOrder = await Order.findOne({ paymentReference: paymentRef });
            if (existingOrder) {
                console.log(`Order ${paymentRef} already exists. Returning existing data.`);
                return res.json({ 
                    success: true, 
                    message: "Payment already verified", 
                    order: existingOrder,
                    // Note: In a real app, you might want to reconstruct 'credentials' 
                    // based on the existing order if needed for the frontend receipt.
                });
            }

            const { 
                productId, 
                productType, 
                planIndex, 
                userId, 
                activationEmail,
                mobileNumber, 
                planAmount,
                firstName,
                lastName,
                address,
                zip,
                osChoice
            } = meta;

            // 2. SANITIZATION
            const extraCPU = parseInt(meta.extraCPU) || 0;
            const extraStorage = parseInt(meta.extraStorage) || 0;
            const cleanPlanIndex = parseInt(planIndex) || 0;
            
            // 3. User Validation
            if (!userId) {
                return res.status(400).json({ success: false, message: "User ID missing in transaction metadata" });
            }
            
            const actualUser = await User.findById(userId);
            if (!actualUser) {
                return res.status(404).json({ success: false, message: "User account not found" });
            }

            const userEmail = actualUser.email; 
            const amountPaid = data.data.amount;
            const currency = data.data.currency;

            let credentials = {};
            let productDetails = { name: "", plan: "" };
            let targetNum = mobileNumber || null;

            // --- 4. HANDLE PRODUCT TYPES ---
            if (productType === "VPN") {
                const item = await VPN.findOneAndUpdate(
                    { _id: productId, stock: { $gt: 0 } },
                    { $inc: { stock: -1 } },
                    { new: true, select: '+password' }
                );
                if (!item) return res.status(400).json({ success: false, message: "VPN out of stock" });

                productDetails.name = item.name;
                productDetails.plan = item.plans[cleanPlanIndex]?.duration || "Standard Plan";
                credentials = {
                    type: "VPN",
                    username: item.username,
                    password: item.password,
                    instructions: item.instructions || "Check dashboard."
                };

            } else if (productType === "Proxy") {
                const item = await Proxy.findOneAndUpdate(
                    { _id: productId, stock: { $gt: 0 } },
                    { $inc: { stock: -1 } },
                    { new: true }
                );
                if (!item) return res.status(400).json({ success: false, message: "Proxy out of stock" });

                productDetails.name = item.name;
                productDetails.plan = `${item.plans[cleanPlanIndex]?.ip_count || 0} IPs`;
                credentials = {
                    type: "Proxy",
                    activationCode: item.activationCode,
                    instructions: item.instructions || "Check dashboard."
                };

            } else if (productType === "RDP") {
                const rdpPlans = {
                    "tier1": { name: "USA Tier 1", ram: "4GB", cpu: "2 Cores", storage: "60GB SSD" },
                    "tier2": { name: "USA Tier 2", ram: "6GB", cpu: "3 Cores", storage: "100GB SSD" },
                    "tier3": { name: "USA Tier 3", ram: "8GB", cpu: "4 Cores", storage: "140GB SSD" },
                    "tier4": { name: "USA Tier 4", ram: "12GB", cpu: "6 Cores", storage: "180GB SSD" },
                    "tier5": { name: "USA Tier 5", ram: "18GB", cpu: "8 Cores", storage: "240GB SSD" },
                    "tier6": { name: "USA Tier 6", ram: "24GB", cpu: "8 Cores", storage: "280GB SSD" }
                };

                const item = rdpPlans[productId];
                if (!item) {
                    return res.status(404).json({ success: false, message: "RDP Plan definition not found." });
                }

                productDetails.name = item.name;
                const cpuDisplay = extraCPU > 0 ? `${item.cpu} (+${extraCPU} Extra)` : item.cpu;
                const storageDisplay = extraStorage > 0 ? `${item.storage} (+${extraStorage}GB Extra)` : item.storage;
                
                productDetails.plan = `${item.ram} RAM | ${cpuDisplay} | ${osChoice || 'Windows Server'}`;
                
                credentials = {
                    type: "RDP",
                    os: osChoice || "Windows Server",
                    specs: `${item.ram} RAM, ${cpuDisplay}, ${storageDisplay}`,
                    instructions: "Your custom RDP is being provisioned. Credentials will be sent to your email within 1-6 hours."
                };
                
            } else if (productType === "eSIM" || productType === "eSIM_Activation") {
                productDetails.name = productId || "eSIM Service"; 
                productDetails.plan = planAmount || "Standard";
                targetNum = mobileNumber;
                credentials = {
                    type: productType,
                    instructions: "Request received. Processing usually takes 5-30 minutes."
                };
            }

            // --- 5. ASSEMBLE ORDER OBJECT ---
            const orderData = {
                userId: userId,
                userEmail: userEmail,
                fullName: (productType === "eSIM_Activation" && firstName) 
                            ? `${firstName} ${lastName}`.trim() 
                            : (actualUser.fullName || "User"),
                productType: productType || "Unknown",
                planName: productDetails.plan || "Generic Plan",
                nodeName: productDetails.name || "Generic Node",
                targetNumber: targetNum,
                amount: amountPaid,
                currency: currency || "USD", 
                status: "successful",
                paymentReference: paymentRef,
                activationCode: credentials.activationCode || null,
                metadata: {
                    address: address || null,
                    zip: zip || null,
                    firstName: firstName || null,
                    lastName: lastName || null,
                    email: activationEmail || null,
                    extraCPU: extraCPU,
                    extraStorage: extraStorage,
                    osChoice: osChoice || null
                }
            };

            if (productType === "VPN") {
                orderData.vpnCredentials = { username: credentials.username, password: credentials.password };
            }
            if (productType === "RDP") {
                orderData.rdpDetails = { os: credentials.os, specs: credentials.specs };
            }

            // --- 6. DATABASE PERSISTENCE ---
            const newOrder = await Order.create(orderData);

            // --- 7. DELIVERY EMAIL (Non-blocking) ---
            try {
                await sendDeliveryEmail(userEmail, credentials, newOrder); 
            } catch (emailErr) {
                console.error("Email Delivery Failed (Order Saved):", emailErr.message);
            }

            return res.json({ 
                success: true, 
                credentials: credentials,
                order: newOrder
            });
        }

        return res.status(400).json({ success: false, message: "Transaction verification failed." });

    } catch (err) {
        console.error("CRITICAL: Payment Verification Error:", err.message);
        return res.status(500).json({ success: false, message: `Internal server error: ${err.message}` });
    }
}

const sendDeliveryEmail = async (userEmail, credentials) => {
    const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASS
        }
    });

    // 1. DYNAMIC CONTENT CONFIGURATION
    const isVPN = credentials.type === "VPN";
    const isRDP = credentials.type === "RDP";
    const isESIM_Refill = credentials.type === "eSIM";
    const isESIM_Activation = credentials.type === "eSIM_Activation";
    const isProxy = credentials.type === "Proxy";
    
    let subject, headerTitle, subHeader;

    if (isRDP) {
        subject = "🖥️ Your RDP Server is Ready!";
        headerTitle = "Server Provisioned!";
        subHeader = "Your high-performance RDP access details are below.";
    } else if (isVPN) {
        subject = "🔑 Your VPN Access Credentials";
        headerTitle = "Node Activated!";
        subHeader = "Your Premium VPN Access is ready.";
    } else if (isESIM_Activation) {
        subject = "📶 eSIM Activation Request Received";
        headerTitle = "Activation in Progress!";
        subHeader = "We are preparing your new eSIM profile.";
    } else if (isESIM_Refill) {
        const isFinal = !!credentials.confirmationNumber;
        subject = isFinal ? "✅ eSIM Refill Confirmed" : "📶 eSIM Refill Request Received";
        headerTitle = isFinal ? "Refill Successful!" : "Processing Refill...";
        subHeader = isFinal 
            ? "Your eSIM has been successfully topped up." 
            : "We have received your refill request and are processing it.";
    } else {
        subject = "🌐 Your Proxy Activation Code";
        headerTitle = "Proxy Ready! 🌐";
        subHeader = "Your Proxy activation details are below.";
    }
    
    // 2. DYNAMIC DATA TABLE
    let dataTableHtml = '';

    if (isRDP) {
        // RDP LAYOUT: Focusing on IP/Login and Hardware Specs
        dataTableHtml = `
            <tr>
                <td class="mobile-full" width="50%" valign="top" style="padding-bottom: 15px;">
                    <span style="font-size: 9px; color: #667085; text-transform: uppercase; font-weight: bold;">Login Credentials (IP/User/Pass)</span><br>
                    <strong style="font-size: 13px; font-family: 'Courier New', monospace; color: #0F54C6;">${credentials.confirmationNumber || credentials.loginDetails || 'Provisioning...'}</strong>
                </td>
                <td class="mobile-full" width="50%" valign="top" style="text-align: right; padding-bottom: 15px;">
                    <span style="font-size: 9px; color: #667085; text-transform: uppercase; font-weight: bold;">Operating System</span><br>
                    <strong style="font-size: 13px; color: #101828;">${credentials.osChoice || 'Windows Server'}</strong>
                </td>
            </tr>
            <tr>
                <td class="mobile-full" width="33%" valign="top">
                    <span style="font-size: 9px; color: #667085; text-transform: uppercase; font-weight: bold;">RAM</span><br>
                    <strong style="font-size: 12px; color: #101828;">${credentials.ram || 'Standard'}</strong>
                </td>
                <td class="mobile-full" width="33%" valign="top" style="text-align: center;">
                    <span style="font-size: 9px; color: #667085; text-transform: uppercase; font-weight: bold;">CPU</span><br>
                    <strong style="font-size: 12px; color: #101828;">${credentials.cpu || 'Standard'}</strong>
                </td>
                <td class="mobile-full" width="33%" valign="top" style="text-align: right;">
                    <span style="font-size: 9px; color: #667085; text-transform: uppercase; font-weight: bold;">Storage</span><br>
                    <strong style="font-size: 12px; color: #101828;">${credentials.storage || 'Standard'}</strong>
                </td>
            </tr>`;
    } else if (isVPN) {
        dataTableHtml = `
            <tr>
                <td class="mobile-full" width="33%" valign="top" style="padding-bottom: 10px;">
                    <span style="font-size: 9px; color: #667085; text-transform: uppercase; font-weight: bold;">Username</span><br>
                    <strong style="font-size: 13px; font-family: 'Courier New', monospace; color: #101828;">${credentials.username}</strong>
                </td>
                <td class="mobile-full" width="33%" valign="top" style="padding-bottom: 10px;">
                    <span style="font-size: 9px; color: #667085; text-transform: uppercase; font-weight: bold;">Security Key</span><br>
                    <strong style="font-size: 13px; font-family: 'Courier New', monospace; color: #0F54C6;">${credentials.password}</strong>
                </td>
                <td class="mobile-full" width="33%" valign="top" style="text-align: right; padding-bottom: 10px;">
                    <span style="font-size: 9px; color: #667085; text-transform: uppercase; font-weight: bold;">Limit</span><br>
                    <strong style="font-size: 13px; color: #101828;">${credentials.deviceLimit || 1} Device(s)</strong>
                </td>
            </tr>`;
    } else if (isESIM_Activation) {
        dataTableHtml = `
            <tr>
                <td class="mobile-full" width="50%" valign="top" style="padding-bottom: 15px;">
                    <span style="font-size: 9px; color: #667085; text-transform: uppercase; font-weight: bold;">Activation Email</span><br>
                    <strong style="font-size: 13px; color: #0F54C6;">${credentials.email || userEmail}</strong>
                </td>
                <td class="mobile-full" width="50%" valign="top" style="text-align: right; padding-bottom: 15px;">
                    <span style="font-size: 9px; color: #667085; text-transform: uppercase; font-weight: bold;">Carrier</span><br>
                    <strong style="font-size: 13px; color: #101828;">${credentials.carrierName || 'Global eSIM'}</strong>
                </td>
            </tr>
            <tr>
                <td class="mobile-full" width="50%" valign="top" style="padding-bottom: 15px;">
                    <span style="font-size: 9px; color: #667085; text-transform: uppercase; font-weight: bold;">Delivery Address</span><br>
                    <strong style="font-size: 12px; color: #344054;">${credentials.address || 'N/A'}</strong>
                </td>
                <td class="mobile-full" width="50%" valign="top" style="text-align: right; padding-bottom: 15px;">
                    <span style="font-size: 9px; color: #667085; text-transform: uppercase; font-weight: bold;">Zip Code</span><br>
                    <strong style="font-size: 13px; color: #101828;">${credentials.zipCode || 'N/A'}</strong>
                </td>
            </tr>
            <tr>
                <td colspan="2" style="border-top: 1px solid #D1E0FF; padding-top: 15px;">
                    <span style="font-size: 9px; color: #667085; text-transform: uppercase; font-weight: bold;">Next Steps</span><br>
                    <p style="font-size: 12px; color: #344054; margin: 5px 0;">Our technical team is generating your unique QR code for <strong>${credentials.planName || 'your plan'}</strong>. This will be sent to <strong>${credentials.email || userEmail}</strong> within 30 minutes.</p>
                </td>
            </tr>`;
    } else if (isESIM_Refill) {
        dataTableHtml = `
            <tr>
                <td class="mobile-full" width="50%" valign="top" style="padding-bottom: 15px;">
                    <span style="font-size: 9px; color: #667085; text-transform: uppercase; font-weight: bold;">Carrier</span><br>
                    <strong style="font-size: 13px; color: #0F54C6;">${credentials.carrierName}</strong>
                </td>
                <td class="mobile-full" width="50%" valign="top" style="text-align: right; padding-bottom: 15px;">
                    <span style="font-size: 9px; color: #667085; text-transform: uppercase; font-weight: bold;">Mobile Number</span><br>
                    <strong style="font-size: 13px; font-family: 'Courier New', monospace; color: #101828;">${credentials.mobileNumber}</strong>
                </td>
            </tr>
            <tr>
                <td class="mobile-full" width="50%" valign="top">
                    <span style="font-size: 9px; color: #667085; text-transform: uppercase; font-weight: bold;">Plan Amount</span><br>
                    <strong style="font-size: 13px; color: #101828;">${credentials.amount || credentials.planAmount}</strong>
                </td>
                <td class="mobile-full" width="50%" valign="top" style="text-align: right;">
                    <span style="font-size: 9px; color: #667085; text-transform: uppercase; font-weight: bold;">Confirmation #</span><br>
                    <strong style="font-size: 13px; font-family: 'Courier New', monospace; color: #F9861E;">${credentials.confirmationNumber || 'PROCESSING'}</strong>
                </td>
            </tr>`;
    } else {
        dataTableHtml = `
            <tr>
                <td class="mobile-full" width="50%" valign="top" style="padding-bottom: 10px;">
                    <span style="font-size: 9px; color: #667085; text-transform: uppercase; font-weight: bold;">Activation Code</span><br>
                    <strong style="font-size: 14px; font-family: 'Courier New', monospace; color: #0F54C6;">${credentials.activationCode || credentials.password}</strong>
                </td>
                <td class="mobile-full" width="50%" valign="top" style="text-align: right; padding-bottom: 10px;">
                    <span style="font-size: 9px; color: #667085; text-transform: uppercase; font-weight: bold;">Amount Paid</span><br>
                    <strong style="font-size: 14px; color: #101828;">${credentials.amount}</strong>
                </td>
            </tr>`;
    }

    const htmlContent = `
    <!DOCTYPE html>
    <html>
    <head>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            @media screen and (max-width: 480px) {
                .mobile-full { width: 100% !important; display: block !important; text-align: left !important; padding-bottom: 15px !important; }
            }
        </style>
    </head>
    <body style="margin: 0; padding: 0; background-color: #f4f7ff;">
        <table border="0" cellpadding="0" cellspacing="0" width="100%">
            <tr>
                <td align="center" style="padding: 20px 0;">
                    <div style="font-family: 'Inter', Helvetica, sans-serif; max-width: 600px; margin: auto; border: 1px solid #e2e8f0; border-radius: 16px; overflow: hidden; background-color: #ffffff;">
                        
                        <div style="background-color: #ffffff; padding: 20px; text-align: center; border-bottom: 1px solid #f0f0f0;">
                            <img src="https://imgur.com/8YeZgfx.png" alt="SMSGlobe" style="height: 24px; width: auto; display: block; margin: 0 auto;">
                        </div>

                        <div style="background-color: #0F54C6; color: white; padding: 35px 24px; text-align: center;">
                            <h2 style="margin: 0; font-size: 22px;">${headerTitle}</h2>
                            <p style="opacity: 0.8; font-size: 13px; margin-top: 8px;">${subHeader}</p>
                        </div>

                        <div style="padding: 24px; color: #344054; text-align: left;">
                            <p style="font-size: 14px; line-height: 1.5; margin-bottom: 24px;">
                                Hello, thank you for choosing <strong>SMSGlobe</strong>. Your order details are provided below.
                            </p>
                            
                            <div style="background: #F0F5FE; padding: 20px; border-radius: 12px; border: 1px solid #D1E0FF; margin-bottom: 24px;">
                                <p style="margin: 0 0 10px 0; font-size: 10px; color: #0F54C6; font-weight: 800; text-transform: uppercase;">Service Details</p>
                                <p style="font-size: 13px; margin: 0 0 20px 0; line-height: 1.6;">${credentials.instructions || 'Please keep this information for your records.'}</p>
                                
                                <table border="0" cellpadding="0" cellspacing="0" width="100%" style="border-top: 1px solid #D1E0FF; padding-top: 15px;">
                                    ${dataTableHtml}
                                </table>
                            </div>

                            <div style="text-align: center; margin-top: 30px;">
                                <a href="https://smsglobe.vercel.app" style="background-color: #0F54C6; color: #ffffff; padding: 12px 24px; text-decoration: none; font-size: 13px; font-weight: bold; border-radius: 8px; display: inline-block;">Access Dashboard</a>
                            </div>
                        </div>

                        <div style="background: #F9FAFB; padding: 20px; text-align: center; border-top: 1px solid #EAECF0;">
                            <p style="font-size: 11px; color: #667085; margin: 0;">&copy; 2026 <strong>SMSGlobe</strong>. All rights reserved.</p>
                        </div>
                    </div>
                </td>
            </tr>
        </table>
    </body>
    </html>`;

    await transporter.sendMail({
        from: `"SMSGlobe Support" <${process.env.EMAIL_USER}>`,
        to: userEmail,
        subject: `${subject} - SMSGlobe`,
        html: htmlContent
    });
};

// 2. GET ALL Proxies (Sorted by Newest)
async function handleGetProxies(req, res) {
    try {
        const proxies = await Proxy.find({}).sort({ createdAt: -1 });
        return res.json({ success: true, proxies });
    } catch (err) {
        return res.status(500).json({ success: false, message: "Fetch failed" });
    }
}

// 3. ADD Proxy (Includes category and stock parsing)
async function handleAddProxy(req, res) {
    try {
        const { name, category, imageUrl, activationCode, instructions, plans, stock } = req.body;

        // Clean and parse the plans
        let formattedPlans = [];
        if (plans && Array.isArray(plans)) {
            formattedPlans = plans.map(p => ({
                ip_count: parseInt(p.ip_count) || 0,
                price: parseFloat(p.price) || 0
            }));
        }

        const newProxy = new Proxy({
            name,
            category: category || 'Standard', 
            imageUrl,
            activationCode,
            instructions,
            stock: parseInt(stock) || 0, // Ensure stock is stored as a number
            plans: formattedPlans
        });

        await newProxy.save();
        return res.json({ success: true, message: "Proxy Package Deployed Successfully" });
    } catch (err) {
        console.error("Add Proxy Error:", err);
        return res.status(500).json({ success: false, message: "Deployment failed" });
    }
}

// 4. UPDATE Proxy (Includes category, stock, and plans update)
async function handleUpdateProxy(req, res) {
    try {
        const { proxyId, plans, stock, ...restOfData } = req.body;

        const updatePayload = { 
            ...restOfData,
            stock: parseInt(stock) || 0 // Parse stock for updates
        };

        // Handle plans parsing specifically
        if (plans && Array.isArray(plans)) {
            updatePayload.plans = plans.map(p => ({
                ip_count: parseInt(p.ip_count) || 0,
                price: parseFloat(p.price) || 0
            }));
        }

        const updated = await Proxy.findByIdAndUpdate(
            proxyId, 
            { $set: updatePayload }, 
            { new: true }
        );
        
        if (!updated) return res.status(404).json({ success: false, message: "Proxy not found" });

        return res.json({ success: true, message: "Proxy Package Updated" });
    } catch (err) {
        console.error("Update Proxy Error:", err);
        return res.status(500).json({ success: false, message: "Update failed" });
    }
}

// 5. DELETE Proxy
async function handleDeleteProxy(req, res) {
    try {
        const { id } = req.query;
        if (!id) return res.status(400).json({ success: false, message: "ID is required" });
        
        await Proxy.findByIdAndDelete(id);
        return res.json({ success: true, message: "Proxy Package Deleted" });
    } catch (err) {
        return res.status(500).json({ success: false, message: "Delete failed" });
    }
}

async function handleAllTransactions(req, res) {
    try {
        const orders = await Order.find().sort({ createdAt: -1 });

        // 2. Map the transactions for the frontend
        const formattedTransactions = orders.map(order => ({
            id: order._id.toString(),
            date: order.createdAt,
            customerName: order.fullName || order.userEmail, 
            email: order.userEmail, 
            product: order.productType,
            details: `${order.nodeName} - ${order.planName}`,
            amount: order.amount,
            currency: order.currency
        }));

        res.json({ 
            success: true, 
            transactions: formattedTransactions 
        });
    } catch (err) {
        console.error("Error fetching transactions:", err);
        res.status(500).json({ success: false, message: "Server error" });
    }
}

async function handleCreateEsimOrder(req, res) {
    const { email, carrierName, mobileNumber, planAmount, refId, productImage } = req.body;
    const USD_TO_NGN_RATE = 1650;

    // Validation
    if (!email || !carrierName || !mobileNumber || !planAmount) {
        return res.status(400).json({ success: false, message: "Missing required eSIM data" });
    }

    try {
        // 1. Clean the USD amount (e.g., "$15.00" -> 15)
        const amountUSD = parseFloat(planAmount.replace(/[$,]/g, ''));
        
        // 2. Calculate the Naira equivalent for your records
        const amountNGN = Math.round(amountUSD * USD_TO_NGN_RATE);

        // 3. Create the order using your existing Order model
        const newOrder = await Order.create({
            userEmail: email,
            productType: 'eSIM',
            nodeName: carrierName,      // Mapping Carrier to nodeName
            planName: planAmount,       // Mapping Plan to planName
            targetNumber: mobileNumber, // The eSIM phone number
            productImage: productImage, // Carrier logo URL
            amount: amountNGN,          // Saving the calculated Naira amount
            currency: 'NGN',
            paymentReference: refId || `REF-${Date.now()}`,
            status: 'pending'           // Stays pending for admin refill
        });

        return res.status(201).json({ 
            success: true, 
            message: "Order created successfully", 
            orderId: newOrder._id 
        });

    } catch (err) {
        console.error("eSIM Creation Error:", err);
        return res.status(500).json({ success: false, message: "Server database error" });
    }
}

async function handleConfirmEsimRefill(req, res) {
    const { tid } = req.query; 
    
    if (!tid) return res.status(400).send("<h1>❌ Missing Transaction ID</h1>");

    try {
        const updatedOrder = await Order.findOneAndUpdate(
            { paymentReference: tid, productType: 'eSIM' },
            { $set: { status: 'Completed', updatedAt: new Date() } },
            { new: true }
        );

        if (updatedOrder) {
            // Trigger the email notification automatically
            try {
                await sendDeliveryEmail(updatedOrder.userEmail, {
                    type: "eSIM",
                    carrierName: updatedOrder.nodeName || "eSIM Carrier",
                    mobileNumber: updatedOrder.targetNumber,
                    instructions: "Your refill has been processed successfully. Please check your device balance."
                });
            } catch (err) { console.error("Email error:", err); }

            return res.send(`
                <div style="font-family: sans-serif; text-align: center; padding: 50px;">
                    <h1 style="color: #0F54C6;">✅ eSIM Refill Confirmed!</h1>
                    <p>The status is now Completed and the user has been notified via email.</p>
                </div>
            `);
        } else {
            return res.send("<h1>ℹ️ Order already processed or not found.</h1>");
        }
    } catch (error) {
        return res.status(500).send("<h1>❌ Server Error</h1>");
    }
}

// GET All eSIM Refills for Admin
async function getEsimRefills(req, res) {
    try {
        const refills = await Order.find({ 
            productType: 'eSIM' 
        })
        .sort({ createdAt: -1 })
        .limit(100);

        const formattedRefills = refills.map(refill => {
            // Convert NGN back to USD
            const amountInUSD = refill.amount / 1650;

            return {
                paymentReference: refill.paymentReference,
                createdAt: refill.createdAt,
                userEmail: refill.userEmail,
                amount: amountInUSD.toFixed(2), 
                status: refill.status || 'pending',
                esimIdentifier: refill.targetNumber || 'N/A',
                carrier: refill.nodeName || refill.carrierName || refill.productName || 'Global eSIM',
                confirmationNumber: refill.confirmationNumber || 'PENDING'
            };
        });

        return res.json({
            success: true,
            refills: formattedRefills 
        });

    } catch (error) {
        console.error("❌ Admin Fetch Error:", error);
        return res.status(500).json({ 
            success: false, 
            message: "Failed to fetch eSIM refill records" 
        });
    }
}

async function handleAdminEsimActivationUpdate(req, res) {
    const { tid, status, confirmationNumber } = req.body;

    if (!tid || !status) {
        return res.status(400).json({ success: false, message: "Missing Transaction ID or Status" });
    }

    try {
        // 1. Update the General Order record
        // We ensure we match the specific productType to avoid accidental updates
        const updatedOrder = await Order.findOneAndUpdate(
            { paymentReference: tid, productType: 'eSIM_Activation' }, 
            { 
                $set: { 
                    status: status, 
                    confirmationNumber: confirmationNumber || null, 
                    updatedAt: new Date() 
                } 
            },
            { new: true } 
        );

        if (!updatedOrder) {
            return res.status(404).json({ success: false, message: "Activation record not found in Orders" });
        }

        // 2. Sync the update to the specialized EsimActivation collection
        await EsimActivation.findOneAndUpdate(
            { paymentReference: tid },
            { 
                $set: { 
                    status: status, 
                    esimProfileId: confirmationNumber || null, 
                    updatedAt: new Date() 
                } 
            }
        );

        const isFinished = status.toLowerCase() === 'completed' || status.toLowerCase() === 'successful';
        
        // 3. Trigger Email for successful activations with Address and Zip included
        if (isFinished) {
            try {
                await sendDeliveryEmail(updatedOrder.userEmail, {
                    type: "eSIM Activation",
                    amount: updatedOrder.planName, 
                    confirmationNumber: confirmationNumber || "Activation Complete",
                    carrierName: updatedOrder.nodeName || "Global eSIM",
                    
                    // --- PERSONAL DATA FROM METADATA ---
                    customerName: `${updatedOrder.metadata?.firstName || ''} ${updatedOrder.metadata?.lastName || ''}`.trim(),
                    shippingAddress: updatedOrder.metadata?.address || "N/A",
                    zipCode: updatedOrder.metadata?.zip || "N/A",
                    // ------------------------------------

                    instructions: "Your eSIM activation is complete. Please use the Profile ID/Activation code provided to set up your device."
                });
            } catch (emailError) {
                console.error("📧 Email Delivery Failed:", emailError);
            }
        }

        return res.json({ 
            success: true, 
            message: `Activation order updated to ${status}`,
            data: updatedOrder 
        });

    } catch (error) {
        console.error("❌ Admin Activation Update Error:", error);
        return res.status(500).json({ success: false, message: "Internal Server error" });
    }
}

async function handleCreateEsimActivation(req, res) {
    // 1. Destructure 'email' from the request body
    const { email, carrierName, mobileNumber, planAmount, metadata, productType } = req.body;
    const userEmail = req.user?.email; 

    // 2. Validation: Ensure the new email field is present
    if (!userEmail || !email || !carrierName || !planAmount) {
        return res.status(400).json({ success: false, message: "Missing required fields (including Email)" });
    }

    try {
        const txRef = `ACT-${Date.now()}-${Math.floor(Math.random() * 1000)}`;

        // 3. Save to EsimActivation collection
        const newActivation = new EsimActivation({
            userEmail,
            email, // <--- Added here
            fullName: `${metadata?.firstName || ''} ${metadata?.lastName || ''}`.trim(),
            nodeName: carrierName,
            planName: planAmount,
            amount: parseFloat(planAmount.replace(/[$,]/g, '')),
            paymentReference: txRef,
            status: 'pending'
        });

        await newActivation.save();

        // 4. Save to General Order record
        const newOrder = new Order({
            userEmail,
            productType: 'eSIM_Activation',
            nodeName: carrierName,
            planName: planAmount,
            amount: newActivation.amount,
            status: 'pending',
            paymentReference: txRef,
            metadata: {
                email, // <--- Store in metadata for the general Order record
                address: metadata?.address,
                zip: metadata?.zip,
                firstName: metadata?.firstName,
                lastName: metadata?.lastName
            }
        });

        await newOrder.save();

        res.json({ 
            success: true, 
            message: "Activation order initialized", 
            tx_ref: txRef 
        });

    } catch (error) {
        console.error("eSIM Activation Order Error:", error);
        res.status(500).json({ success: false, error: "Internal Server Error" });
    }
}

// Renamed to match the switch case exactly
async function handleGetEsimActivations(req, res) { 
    try {
        const activations = await Order.find({ 
            productType: 'eSIM_Activation' 
        })
        .sort({ createdAt: -1 })
        .limit(100);

        const formattedActivations = activations.map(activation => {
            const amountInUSD = activation.amount / 1650;
            
            // Check both activationDetails (new schema) and metadata (old schema)
            const details = activation.activationDetails || activation.metadata || {};

            return {
                paymentReference: activation.paymentReference,
                productType: 'eSIM_Activation', 
                createdAt: activation.createdAt,
                userEmail: activation.userEmail, 
                email: details.email || activation.userEmail || 'N/A',
                fullName: `${details.firstName || ''} ${details.lastName || ''}`.trim() || activation.fullName || 'N/A',
                amount: amountInUSD.toFixed(2), 
                status: activation.status || 'pending',
                nodeName: activation.targetNumber || activation.nodeName || activation.carrierName || 'eSIM Device',
                
                planName: activation.planName || 'Standard Plan',
                confirmationNumber: activation.confirmationNumber || 'PENDING',
                
                address: details.address || 'N/A',
                zipCode: details.zip || details.zipCode || 'N/A'
            };
        });

        return res.json({
            success: true,
            orders: formattedActivations 
        });

    } catch (error) {
        console.error("❌ Admin Fetch Error:", error);
        return res.status(500).json({ 
            success: false, 
            message: "Failed to fetch eSIM activation records" 
        });
    }
}

// GET: Fetch all RDP plans (for Admin list or User selection)
async function handleGetRDPs(req, res) {
    try {
        const rdps = await RDP.find({}).sort({ createdAt: -1 });
        res.json({ success: true, rdps });
    } catch (error) {
        console.error("Fetch RDP Error:", error);
        res.status(500).json({ success: false, message: "Failed to fetch RDP plans" });
    }
}

// POST: Add a new RDP plan
async function handleAddRDP(req, res) {
    const { name, category, ram, cpu, storage, network, os, price, isInstant, instructions } = req.body;
    
    if (!name || !ram || !cpu || !storage || !price) {
        return res.status(400).json({ success: false, message: "Missing required RDP fields" });
    }

    try {
        const newRDP = new RDP({
            name, category, ram, cpu, storage, network, os, 
            price, isInstant, instructions,
            adminUpdatedBy: req.user?.email
        });
        await newRDP.save();
        res.json({ success: true, message: "RDP Plan added successfully", rdp: newRDP });
    } catch (error) {
        console.error("Add RDP Error:", error);
        res.status(500).json({ success: false, message: "Server error while adding RDP" });
    }
}

async function handleCompleteRDPOrder(req, res) {
    const { tid, status, confirmationNumber } = req.body;

    try {
        // 1. Update the order in MongoDB
        const order = await Order.findOneAndUpdate(
            { paymentReference: tid },
            { 
                status: status || 'completed',
                confirmationNumber: confirmationNumber, // Stores IP/Login Details
                deliveredAt: new Date()
            },
            { new: true }
        );

        if (!order) {
            return res.status(404).json({ success: false, message: "Order not found" });
        }

        // 2. Trigger the Email Notification
        // We pass the RDP metadata so the email shows RAM, CPU, etc.
        try {
            await sendDeliveryEmail(order.userEmail, { 
                type: 'RDP', 
                confirmationNumber: confirmationNumber, // This is the IP/Login details
                osChoice: order.metadata?.osChoice || 'Windows Server',
                ram: order.metadata?.ram || 'Standard',
                cpu: order.metadata?.cpu || 'Standard',
                storage: order.metadata?.storage || 'Standard',
                instructions: order.instructions || "Your RDP server is now active. Use the credentials below to connect via Remote Desktop Connection."
            });
        } catch (mailError) {
            console.error("Email failed to send, but order was updated:", mailError);
            // We don't return error here because the DB update was successful
        }

        res.json({ 
            success: true, 
            message: "RDP marked as delivered and email sent.", 
            order 
        });

    } catch (error) {
        console.error("RDP Completion Error:", error);
        res.status(500).json({ success: false, message: "Server error during RDP completion" });
    }
}

// DELETE: Remove an RDP plan
async function handleDeleteRDP(req, res) {
    const { id } = req.body;
    try {
        await RDP.findByIdAndDelete(id);
        res.json({ success: true, message: "RDP Plan deleted" });
    } catch (error) {
        res.status(500).json({ success: false, message: "Delete failed" });
    }
}

async function handleGetRdpRequests(req, res) {
    try {
        const requests = await Order.find({ productType: 'RDP' })
            .sort({ createdAt: -1 })
            .limit(100);

        const formattedRequests = requests.map(order => {
            // If order.amount is already in Naira (e.g., 25000), 
            // we send it as is. If you need it in USD for the UI, 
            // keep the division. Otherwise, just format it.
            const nairaAmount = parseFloat(order.amount) || 0;

            return {
                paymentReference: order.paymentReference,
                productType: 'RDP',
                createdAt: order.createdAt,
                userEmail: order.userEmail,
                fullName: order.metadata?.fullName || 'N/A',
                nodeName: order.nodeName || 'Tier Plan',
                planName: order.planName || 'RDP Server',
                osChoice: order.metadata?.osChoice || 'Windows',
                
                // Hardware specs
                ram: order.metadata?.ram || 'N/A',
                cpu: order.metadata?.cpu || 'N/A',
                storage: order.metadata?.storage || 'N/A',
                
                // Addons
                extraCPU: order.metadata?.extraCPU || 0,
                extraStorage: order.metadata?.extraStorage || 0,
                
                // Keep as Naira for the Admin Table
                amount: nairaAmount.toLocaleString('en-NG', { minimumFractionDigits: 2 }), 
                status: order.status || 'pending',
                confirmationNumber: order.confirmationNumber || 'PENDING'
            };
        });

        return res.json({
            success: true,
            orders: formattedRequests
        });

    } catch (error) {
        console.error("❌ RDP Fetch Error:", error);
        return res.status(500).json({ success: false, message: "Failed to fetch RDP requests" });
    }
}

async function getTextverifiedToken() {
    try {
        const response = await axios.post(
            'https://www.textverified.com/api/SimpleAuthentication', 
            {}, 
            { 
                headers: { 
                    // Use the correct header for Textverified V2
                    'X-API-KEY': process.env.TEXTVERIFIED_V2_KEY,
                    'Accept': 'application/json'
                } 
            }
        );
        return response.data.bearer_token;
    } catch (err) {
        console.error("Textverified Auth Failed. Check your Vercel Environment Variables.");
        return null;
    }
}

// --- Updated: Fetch Numbers (Inventory) ---
async function handleGetNumbers(req, res) {
    const { country, service } = req.query; // country (e.g., 'US'), service (e.g., 'WhatsApp')

    if (!service) return res.status(400).json({ success: false, message: "Service is required." });

    try {
        const token = await getTextverifiedToken();
        if (!token) throw new Error("Could not authenticate with Textverified");

        // 1. Find the Target ID for the service
        const targetsRes = await axios.get('https://www.textverified.com/api/Targets', {
            headers: { Authorization: `Bearer ${token}` }
        });

        // Search for the service name in the targets list
        const target = targetsRes.data.find(t => 
            t.name.toLowerCase().includes(service.toLowerCase())
        );

        if (!target) {
            return res.json({ success: false, message: `Service '${service}' not found on Textverified.` });
        }

        // 2. Fetch costs/availability for this target
        // Note: Textverified API works per-request. We simulate a batch of 1 for the UI.
        return res.json({ 
            success: true, 
            numbers: [`Ready to Activate ${target.name}`], // Placeholder to trigger selection in your UI
            targetId: target.id,
            cost: target.cost
        });

    } catch (err) {
        console.error("Textverified Inventory Error:", err);
        return res.status(500).json({ success: false, message: "Failed to sync with Textverified." });
    }
}

// --- Backend: handleGetStock ---
async function handleGetStock(req, res) {
    try {
        const token = await getTextverifiedToken();
        if (!token) return res.json({ success: false, message: "Auth failed" });

        // Fetch all targets (services/countries) from Textverified
        const response = await axios.get('https://www.textverified.com/api/Targets', {
            headers: { Authorization: `Bearer ${token}` }
        });

        const stockData = {};
        // We map the target ID to the cost so your frontend can show prices
        response.data.forEach(t => {
            stockData[t.id] = t.cost; 
        });

        return res.json({ 
            success: true, 
            stock: stockData // This matches your frontend 'res.stock'
        });
    } catch (err) {
        console.error("Stock Sync Error:", err.message);
        return res.json({ success: false, stock: {}, message: "Stock sync failed" });
    }
}

// --- Updated: Activate/Purchase Number ---
async function handleActivatePurchase(req, res) {
    const { targetId, price, type } = req.body; 

    try {
        const token = await getTextverifiedToken();
        
        // 1. Create the verification (This actually buys the number)
        const response = await axios.post(
            'https://www.textverified.com/api/Verifications',
            { targetId: targetId },
            { headers: { Authorization: `Bearer ${token}` } }
        );

        const verification = response.data; // Contains { id, number, status, etc }

        // 2. Log this in your local database here (RentalId = verification.id)
        
        return res.json({
            success: true,
            rentalId: verification.id,
            number: verification.number,
            message: "Number Reserved!"
        });
    } catch (err) {
        console.error("Purchase Error:", err.response?.data);
        return res.status(500).json({ 
            success: false, 
            message: err.response?.data?.message || "Purchase failed." 
        });
    }
}

// --- 8. STARTUP ---
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

if (process.env.NODE_ENV !== 'production') {
    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () => console.log(`Dev Server: http://localhost:${PORT}`));
}

module.exports = app;