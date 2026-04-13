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
const crypto = require('crypto');

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

// Manually serve sitemap.xml
app.get('/sitemap.xml', (req, res) => {
    res.sendFile(path.join(__dirname, 'sitemap.xml'));
});

// Manually serve robots.txt
app.get('/robots.txt', (req, res) => {
    res.sendFile(path.join(__dirname, 'robots.txt'));
});

// --- 2. CONFIGURATION & SCHEMA ---
const JWT_SECRET = process.env.JWT_SECRET;
const RECAPTCHA_SECRET = process.env.RECAPTCHA_SECRET_KEY;

// --- ADMIN SCHEMA ---
const adminSchema = new mongoose.Schema({
    fullName: { type: String, required: true },
    email: { type: String, required: true, unique: true, index: true },
    password: { type: String, required: true },
    resetPasswordToken: { type: String },
    resetPasswordExpires: { type: Date }
}, { timestamps: true });

const Admin = mongoose.models.Admin || mongoose.model('Admin', adminSchema);

const userSchema = new mongoose.Schema({
    fullName: { type: String, required: [true, "Full name is required"], trim: true },
    email: { 
        type: String, 
        required: [true, "Email is required"], 
        unique: true, 
        lowercase: true, 
        trim: true,
        match: [/^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/, 'Please fill a valid email address']
    },
    password: { type: String, required: [true, "Password is required"], select: false },    
    balance: { type: Number, default: 0, min: [0, "Balance cannot be negative"] },   
    bonusBalance: { type: Number, default: 0 },    
    hasDeposited: { type: Boolean, default: false },
    status: { type: String, enum: ['active', 'suspended'], default: 'active', index: true },
    referralCode: { type: String, unique: true, sparse: true, uppercase: true, trim: true },
    referredBy: { type: String, default: null, index: true },
    referralCount: { type: Number, default: 0 },
    resetPasswordToken: String,
    resetPasswordExpires: Date
}, { timestamps: true });

userSchema.index({ email: 1, referralCode: 1 });
const User = mongoose.models.User || mongoose.model('User', userSchema);

// --- SYSTEM SETTINGS (Exchange Rate Removed) ---
const systemSettingsSchema = new mongoose.Schema({
    maintenanceMode: { type: Boolean, default: false },
    allowSignups: { type: Boolean, default: true },    
    globalMarkup: { type: Number, default: 0 }, 
    noticeBarText: { type: String, default: "Welcome to SMSGlobe!" },
    supportWhatsapp: { type: String, default: "" }
}, { timestamps: true });

const SystemSettings = mongoose.models.SystemSettings || mongoose.model('SystemSettings', systemSettingsSchema, 'system_settings');

const vpnSchema = new mongoose.Schema({
    name: { type: String, required: true },
    provider: { type: String, required: true },
    region: { type: String, required: true },
    image: { type: String },     
    deviceType: { type: String, enum: ['Phone', 'PC', 'Both'], default: 'Both' },
    stock: { type: Number, default: 0 },
    deviceLimit: { type: Number, default: 1 }, // Added to match your frontend
    plans: [{
        duration: { type: String, required: true },
        price: { type: Number, required: true } // Price in NGN
    }],        
    username: { type: String },
    password: { type: String, select: false },     
    pcMethod: { type: String }, // e.g., 'User/Pass' or 'Activation Code'
    pcUsername: { type: String },
    pcPassword: { type: String, select: false },
    activationCode: { type: String },
    
    instructions: { type: String }
}, { timestamps: true });

const VPN = mongoose.models.VPN || mongoose.model('VPN', vpnSchema);

const ProxySchema = new mongoose.Schema({
    name: { type: String, required: true },
    category: { type: String, default: 'Standard' },
    stock: { type: Number, default: 0 },
    plans: [{
        ip_count: { type: Number, required: true },
        price: { type: Number, required: true } 
    }],
    activationCode: String,
    instructions: { type: String, default: "Check dashboard for details." }
}, { timestamps: true });

const Proxy = mongoose.models.Proxy || mongoose.model('Proxy', ProxySchema);

const rdpSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    userEmail: String,
    fullName: String,
    productType: { type: String, default: "RDP" },
    planName: String,
    nodeName: String, 
    ram: String, cpu: String, storage: String, net: String, os: String,
    amount: Number,
    extraCPU: { type: Number, default: 0 },
    extraStorage: { type: Number, default: 0 },
    currency: { type: String, default: "NGN" },
    status: { type: String, default: "successful" },
    paymentReference: String,
    metadata: { extraCPU: Number, extraStorage: Number, osChoice: String }
}, { timestamps: true });

const RDP = mongoose.models.RDP || mongoose.model('RDP', rdpSchema, 'rdp_orders');

// --- TRANSACTION SCHEMA ---
const transactionSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    type: { type: String, enum: ['credit', 'debit'], required: true },
    purpose: { type: String, enum: ['deposit', 'purchase', 'refund', 'referral_bonus'], required: true },
    amountNGN: { type: Number, required: true, set: v => Math.round(v * 100) / 100 },
    status: { type: String, enum: ['pending', 'successful', 'failed'], default: 'pending', index: true },
    reference: { type: String, unique: true, required: true, trim: true },
    paymentMethod: { type: String, default: 'wallet' },     
    balanceBefore: { type: Number, default: 0 },
    balanceAfter: { type: Number, default: 0 },
    bonusBefore: { type: Number, default: 0 }, // New field
    bonusAfter: { type: Number, default: 0 },  // New field

    metadata: { type: mongoose.Schema.Types.Mixed } 
}, { timestamps: true });

const Transaction = mongoose.models.Transaction || mongoose.model('Transaction', transactionSchema);

const orderSchema = new mongoose.Schema({
    userEmail: { type: String, required: true, index: true },
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    fullName: { type: String },         
    productType: { 
        type: String, 
        enum: ['VPN', 'Proxy', 'eSIM', 'eSIM_Refill', 'eSIM_Activation', 'RDP', 'RentedNumber'], 
        required: true 
    },
    planName: String, 
    nodeName: String, 
    amount: { type: Number, required: true }, // Total cost
    currency: { type: String, default: 'NGN' },     
    mainBalanceUsed: { type: Number, default: 0 }, 
    bonusBalanceUsed: { type: Number, default: 0 }, 
    status: { type: String, enum: ['pending', 'successful', 'failed', 'completed'], default: 'pending' }, 
    paymentReference: { type: String, unique: true },    
    ram: String,
    cpu: String,
    storage: String,
    net: String,
    os: String,
    extraCPU: { type: Number, default: 0 },
    extraStorage: { type: Number, default: 0 },
    activationCode: String, 
    vpnCredentials: { username: String, password: { type: String } },
    rdpDetails: { os: String, specs: String },
    
    metadata: { type: mongoose.Schema.Types.Mixed } 
    
}, { timestamps: true });

const Order = mongoose.models.Order || mongoose.model('Order', orderSchema);

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

const verifyToken = async (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(403).json({ success: false, error: "No token provided" });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;

        const User = mongoose.models.User || mongoose.model('User');
        const userRecord = await User.findById(decoded.id).select('status');

        if (!userRecord) {
            return res.status(404).json({ success: false, error: "User no longer exists" });
        }

        if (userRecord.status === 'suspended') {
            return res.status(403).json({ 
                success: false, 
                error: "Session terminated. Your account is suspended.",
                isSuspended: true 
            });
        }

        next();
    } catch (err) {
        console.error("Token Verification Error:", err.message);
        return res.status(401).json({ success: false, error: "Unauthorized or expired session" });
    }
};

async function getReferrals(user) {
    // This only works after 'User' is defined above
    const count = await User.countDocuments({ referredBy: user.referralCode });
    return count;
}
async function generateUniqueCode() {
    let isUnique = false;
    let code = "";
    while (!isUnique) {
        // Generates 3 random bytes -> 6 hex characters (e.g., 7F2A9B)
        code = crypto.randomBytes(3).toString('hex').toUpperCase();
        const existing = await User.findOne({ referralCode: code });
        if (!existing) isUnique = true;
    }
    return code;
}

function normalizeDeviceType(type) {
    if (!type) return 'Phone';
    const t = type.toLowerCase();
    if (t === 'phone') return 'Phone';
    if (t === 'pc') return 'PC';
    if (t === 'both') return 'Both';
    return 'Phone'; // Default fallback
}

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
        case 'user-orders': return handleGetUserOrders(req, res);
        case 'change-password': return handleChangePassword(req, res);
        case 'forgot-password': return handleForgotPasswordRequest(req, res);
        case 'reset-password': return handleResetPassword(req, res);
        case 'purchase-vpn': return handlePurchaseVPN(req, res);
        case 'initiate-topup': return handleInitiateTopup(req, res);
        case 'verify-topup': return handleVerifyTopup(req, res);
        case 'purchase-with-wallet': return handlePurchaseWithWallet(req, res);
        case 'proxies': 
            if (req.method === 'GET') return handleGetProxies(req, res);
            if (req.method === 'POST') return handleAddProxy(req, res);
            if (req.method === 'PATCH') return handleUpdateProxy(req, res);
            if (req.method === 'DELETE') return handleDeleteProxy(req, res);
            break;
        case 'transactions': return handleAllTransactions(req, res);
        case 'user-transactions': return handleGetUserTransactions(req, res);
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
        case 'get-numbers/numbers': 
    case 'get-numbers': 
    return handleGetNumbers(req, res);

       case 'rentals/activate':
case 'purchase/process':
case 'activate-number': // If your frontend uses this
    return handleActivatePurchase(req, res);
case 'change-passwords': 
    if (req.method === 'POST') return handleAdminChangePassword(req, res);
    break;
    case 'admin-forgot-password':
    if (req.method === 'POST') return handleAdminForgotPasswordRequest(req, res);
    break;

case 'admin-reset-password':
    if (req.method === 'POST') return handleAdminResetPassword(req, res);
    break;
  // Change this in your router file
case 'update-system-settings': 
    if (req.method === 'POST') return handleUpdateSystemSettings(req, res);
    break;
case 'get-system-settings':
case 'system-settings': 
    if (req.method === 'GET') return handleGetSystemSettings(req, res);
    break;
case 'system-status': // Public route for the frontend to check
    return handleGetSystemStatus(req, res);
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

    // 1. RECAPTCHA VERIFICATION
    const isHuman = await verifyRecaptcha(captchaToken);
    
    if (!isHuman) {
        // This is where your 400 error is coming from. 
        // Ensure your frontend is sending 'captchaToken' in the JSON body.
        console.log(`Admin login blocked: reCAPTCHA failed for ${email}`); 
        return res.status(400).json({ 
            success: false, 
            message: "reCAPTCHA verification failed. Please refresh and try again." 
        });
    }

    try {
        // 2. ADMIN AUTHENTICATION
        const admin = await Admin.findOne({ email });
        
        if (!admin || !(await bcrypt.compare(password, admin.password))) {
            return res.status(401).json({ success: false, message: "Invalid admin credentials" });
        }

        // 3. TOKEN GENERATION
        const token = jwt.sign(
            { id: admin._id, email: admin.email, role: 'admin' }, 
            JWT_SECRET, 
            { expiresIn: '24h' }
        );

        return res.json({ success: true, token });
    } catch (err) {
        console.error("Admin Login Error:", err);
        return res.status(500).json({ success: false, message: "Internal server error" });
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

        const now = new Date();
        const startOfDay = new Date(); startOfDay.setHours(0,0,0,0);
        const startOfWeek = new Date(); startOfWeek.setDate(now.getDate() - 7);
        const startOfMonth = new Date(now.getFullYear(), now.getMonth(), 1);
        const startOfYear = new Date(now.getFullYear(), 0, 1);

        const validStatuses = ['successful', 'completed', 'paid'];

        const orders = await Order.find({ 
            status: { $in: validStatuses } 
        });

        // Simplified to only NGN
        let ngnStats = { totalRevenue: 0, daily: 0, weekly: 0, monthly: 0, yearly: 0 };

        orders.forEach(order => {
            const amount = parseFloat(order.amount || 0);
            const date = new Date(order.createdAt || now);
            
            // We assume all orders are treated as NGN value now
            ngnStats.totalRevenue += amount;
            if (date >= startOfDay) ngnStats.daily += amount;
            if (date >= startOfWeek) ngnStats.weekly += amount;
            if (date >= startOfMonth) ngnStats.monthly += amount;
            if (date >= startOfYear) ngnStats.yearly += amount;
        });

        const rawRecentOrders = await Order.find({ 
            status: { $in: validStatuses } 
        })
        .sort({ createdAt: -1 })
        .limit(10);

        const recentOrders = rawRecentOrders.map(order => ({
            userEmail: order.userEmail,
            productType: order.productType || order.planName,
            status: order.status,
            amount: parseFloat(order.amount || 0), 
            createdAt: order.createdAt
        }));

        // Chart logic
        const chartLabels = [];
        const chartData = [];
        for (let i = 6; i >= 0; i--) {
            const d = new Date();
            d.setDate(d.getDate() - i);
            chartLabels.push(d.toLocaleDateString('en-US', { weekday: 'short' }));

            const start = new Date(d); start.setHours(0,0,0,0);
            const end = new Date(d); end.setHours(23,59,59,999);

            const dayCount = orders.filter(o => {
                const orderDate = new Date(o.createdAt);
                return orderDate >= start && orderDate <= end;
            }).length;
            
            chartData.push(dayCount);
        }

        return res.json({ 
            success: true, 
            totalUsers,
            revenue: ngnStats, // Renamed to generic revenue
            recentOrders,
            chart: { labels: chartLabels, data: chartData } 
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
                _id: u._id,
                fullName: u.fullName || 'Member',
                email: u.email,
                status: u.status || 'active',
                balance: u.balance || 0,           // Added balance
                referralCode: u.referralCode || 'N/A', // Added referral code
                referralCount: u.referralCount || 0,   // Added count
                createdAt: u.createdAt
            }))
        });
    } catch (err) {
        console.error("Fetch Users Error:", err);
        return res.status(500).json({ success: false, message: "Database Error" });
    }
}
async function handleManageUser(req, res) {
    const { action, userId } = req.body;
    console.log("API RECEIVED:", req.body);

    if (!userId || !action) {
        return res.status(400).json({ success: false, message: "Missing User ID or Action." });
    }

    try {
        // Ensure Database Connection is active (Critical for serverless)
        if (mongoose.connection.readyState !== 1) {
            return res.status(500).json({ success: false, message: "Database connection lost." });
        }

        const User = mongoose.models.User || mongoose.model('User', new mongoose.Schema({}, { strict: false }), 'users');
        
        // 1. Handle Deletion
        if (action === 'delete') {
            const deleted = await User.findByIdAndDelete(userId);
            if (!deleted) return res.status(404).json({ success: false, message: "User not found." });
            return res.json({ success: true, message: "User deleted." });
        }

        // 2. Map actions to statuses
        const statusMap = {
            'suspend': 'suspended',
            'activate': 'active'
        };

        const newStatus = statusMap[action];
        if (!newStatus) {
            return res.status(400).json({ success: false, message: "Invalid action type." });
        }

        // 3. Update and Return
        const updatedUser = await User.findByIdAndUpdate(
            userId, 
            { $set: { status: newStatus } }, 
            { new: true }
        );

        if (!updatedUser) {
            return res.status(404).json({ success: false, message: "User not found." });
        }

        return res.json({ 
            success: true, 
            message: `User is now ${newStatus}.`,
            status: updatedUser.status 
        });

    } catch (err) {
        console.error("Manage User Error:", err);
        return res.status(500).json({ success: false, message: err.message });
    }
}
async function handleGetVPNs(req, res) {
    try {
        const vpns = await VPN.find({})
            .sort({ createdAt: -1 })
            // Ensure stock and deviceLimit are included in the selection
            .select('+password +pcPassword +activationCode +deviceType +stock +deviceLimit'); 
            
        res.json({ success: true, products: vpns }); 
    } catch (err) {
        console.error("Fetch VPN Error:", err);
        res.status(500).json({ success: false, message: "Failed to fetch VPN list" });
    }
}
async function handleAddVPN(req, res) {
    try {
        // 1. Destructure to extract plans and deviceType for explicit handling
        const { plans, deviceType, stock, deviceLimit, price, ...otherData } = req.body;
        let formattedPlans = [];
        if (plans && Array.isArray(plans)) {
            formattedPlans = plans.map(p => ({
                duration: p.duration || "1 Month", // Default duration if missing
                price: Math.round(parseFloat(p.price)) || 0
            }));
        }
        const newVPN = new VPN({
            ...otherData, 
            plans: formattedPlans,  
            deviceType: deviceType ? normalizeDeviceType(deviceType) : 'Phone',            
            stock: parseInt(stock) || 0, 
            deviceLimit: parseInt(deviceLimit) || 1,             
            price: formattedPlans.length > 0 
                ? formattedPlans[0].price 
                : (Math.round(parseFloat(price)) || 0)
        });
        await newVPN.save();

        res.status(201).json({ 
            success: true, 
            message: "VPN Node & Stock Synced Successfully",
            productId: newVPN._id 
        });
        
    } catch (err) {
        console.error("Add VPN Error:", err);
        res.status(500).json({ 
            success: false, 
            message: "Upload failed: " + err.message 
        });
    }
}

async function handleUpdateVPN(req, res) {
    try {
        const { vpnId, id, ...updateData } = req.body;
        const targetId = vpnId || id;

        if (!targetId) {
            return res.status(400).json({ success: false, message: "VPN ID is required" });
        }
        if (updateData.deviceType) {
            updateData.deviceType = normalizeDeviceType(updateData.deviceType);
        }
        if (updateData.plans && Array.isArray(updateData.plans)) {
            updateData.plans = updateData.plans.map(p => ({
                duration: p.duration || "1 Month",
                price: Math.round(parseFloat(p.price)) || 0
            }));
            
            if (updateData.plans.length > 0) {
                updateData.price = updateData.plans[0].price;
            }
        } else if (updateData.price !== undefined) {
            updateData.price = Math.round(parseFloat(updateData.price)) || 0;
        }
        if (updateData.stock !== undefined) {
            updateData.stock = parseInt(updateData.stock) || 0;
        }
        if (updateData.deviceLimit !== undefined) {
            updateData.deviceLimit = parseInt(updateData.deviceLimit) || 1;
        }
        const updated = await VPN.findByIdAndUpdate(
            targetId, 
            { $set: updateData }, 
            { new: true, runValidators: true }
        );
        if (!updated) {
            return res.status(404).json({ success: false, message: "VPN node not found" });
        }

        res.json({ 
            success: true, 
            message: "VPN Configuration Updated Successfully",
            data: updated 
        });

    } catch (err) {
        console.error("Update VPN Error:", err);
        res.status(500).json({ 
            success: false, 
            message: "Update failed: " + err.message 
        });
    }
}
async function handleDeleteVPN(req, res) {
    try {
        const { id } = req.query;
        if (!id) return res.status(400).json({ success: false, message: "ID is required" });
        
        const deleted = await VPN.findByIdAndDelete(id);
        
        if (!deleted) {
            return res.status(404).json({ success: false, message: "VPN node not found" });
        }
        res.json({ success: true, message: "VPN Node Deleted Successfully" });
    } catch (err) {
        console.error("Delete VPN Error:", err);
        res.status(500).json({ success: false, message: "Delete failed" });
    }
}

async function handleUserLogin(req, res) {
    console.log("Incoming Login Data:", req.body);
    const { email, password, captchaToken } = req.body;
    if (!email || typeof email !== 'string') {
        return res.status(400).json({ success: false, message: "Valid email is required." });
    }
    if (!password || typeof password !== 'string') {
        return res.status(400).json({ success: false, message: "Password is required." });
    }

    if (!captchaToken) {
        return res.status(400).json({ success: false, message: "reCAPTCHA token missing." });
    }
    try {
        const isHuman = await verifyRecaptcha(captchaToken);
        if (!isHuman) {
            return res.status(400).json({ success: false, message: "Security verification failed." });
        }
    } catch (recaptchaErr) {
        console.error("reCAPTCHA Service Error:", recaptchaErr.message);
    }
    try {
        const settings = await SystemSettings.findOne(); 
        if (settings && settings.maintenanceMode === true) {
            return res.status(503).json({ 
                success: false, 
                message: "SMSGlobe is currently under maintenance. Please try again later." 
            });
        }
    const user = await User.findOne({ email: email.toLowerCase().trim() }).select('+password');        
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ success: false, message: "Invalid email or password." });
        }
        if (user.status === 'suspended') {
            return res.status(403).json({ 
                success: false, 
                message: "Your account has been suspended for violating SMSGlobe rules. Contact support." 
            });
        }
        if (!JWT_SECRET) {
            throw new Error("JWT_SECRET is not defined in environment variables.");
        }

        const token = jwt.sign(
            { id: user._id, email: user.email, type: 'user' }, 
            JWT_SECRET, 
            { expiresIn: '24h' }
        );

        return res.json({ 
            success: true, 
            token,
            user: { 
                name: user.fullName, 
                email: user.email, 
                balance: user.balance || 0,
                bonusBalance: user.bonusBalance || 0,
                hasDeposited: user.hasDeposited || false
            } 
        });

    } catch (err) {
        // Log the stack trace so you know exactly which line failed in your terminal
        console.error("========== LOGIN ERROR ==========");
        console.error("Message:", err.message);
        console.error("Stack:", err.stack);
        console.error("=================================");
        
        return res.status(500).json({ 
            success: false, 
            message: "Internal server error.",
            // Only send error details to frontend if in development mode
            dev_hint: err.message 
        });
    }
}

async function handleUserRegister(req, res) {
    const { fullName, email, password, captchaToken, friendReferralCode } = req.body;

    // 1. reCAPTCHA Validation
    if (!captchaToken) {
        return res.status(400).json({ success: false, message: "reCAPTCHA token missing." });
    }

    const isHuman = await verifyRecaptcha(captchaToken);
    if (!isHuman) {
        return res.status(400).json({ success: false, message: "reCAPTCHA verification failed." });
    }

    try {
        const normalizedEmail = email.toLowerCase().trim();

        // 2. Check if user already exists
        const existingUser = await User.findOne({ email: normalizedEmail });
        if (existingUser) {
            return res.status(400).json({ success: false, message: "This email is already registered." });
        }

        let referredBy = null;

        // 3. Handle Referral Logic
        if (friendReferralCode && friendReferralCode.trim().length > 0) {
            const cleanFriendCode = friendReferralCode.trim().toUpperCase();            
            const referrer = await User.findOne({ referralCode: cleanFriendCode });
            
            if (referrer) {
                referredBy = referrer.referralCode;
                
                // UPDATE: Add the $2,000 bonus to the REFERRER
                referrer.bonusBalance = (referrer.bonusBalance || 0) + 3000;
                referrer.referralCount = (referrer.referralCount || 0) + 1;
                
                await referrer.save();
            } else {
                return res.status(400).json({ 
                    success: false, 
                    message: "The referral code provided is invalid. Leave it blank if you don't have one." 
                });
            }
        }
        const myNewReferralCode = await generateUniqueCode();
        const hashedPassword = await bcrypt.hash(password, 12);                
        const newUser = new User({ 
            fullName: fullName.trim(), 
            email: normalizedEmail, 
            password: hashedPassword,
            balance: 0,             // Main wallet (Real money)
            bonusBalance: 0,        // Starting bonus for new user
            hasDeposited: false,    // Bonus remains locked until this is true
            referralCode: myNewReferralCode,
            referredBy: referredBy           
        });
        
        await newUser.save();
        
        return res.status(201).json({ 
            success: true, 
            message: "Account created successfully! You can now log in.",
            referralCode: myNewReferralCode 
        });

    } catch (err) {
        console.error("Registration Error:", err);
        return res.status(500).json({ success: false, message: "Failed to create account. Please try again." });
    }
}

// Fetch profile for the logged-in user (NGN Only)
async function handleGetUserProfile(req, res) {
    // 1. Verify token
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) return res.status(401).json({ success: false, message: "No token provided" });

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        
        // Select all fields except password
        const user = await User.findById(decoded.id).select('-password');
        
        if (!user) {
            return res.status(404).json({ success: false, message: "User not found" });
        }

        // 2. Check for suspension
        if (user.status === 'suspended') {
            return res.status(403).json({ 
                success: false, 
                message: "Account suspended",
                status: 'suspended' 
            });
        }
        
        // 3. Return user data (Removed USD fields)
        return res.json({ 
            success: true, 
            _id: user._id,
            fullName: user.fullName,
            email: user.email, 
            status: user.status || 'active',
            balance: user.balance || 0, 
            bonusBalance: user.bonusBalance || 0, 
            hasDeposited: user.hasDeposited || false,
            referralCode: user.referralCode || "", 
            referralCount: user.referralCount || 0 
        });

    } catch (err) {
        console.error("JWT Verification Error:", err.message);
        return res.status(401).json({ success: false, message: "Unauthorized or expired token" });
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



// --- 1. Initiate Topup (NGN Only) ---
async function handleInitiateTopup(req, res) {
    const { amountNGN } = req.body; // Changed from amountUSD
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token || !amountNGN) {
        return res.status(400).json({ success: false, message: "Missing required data" });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        
        const user = await User.findById(decoded.id);
        if (!user) return res.status(404).json({ success: false, message: "User not found" });

        // Calculate Final Amount: amount + globalMarkup (if markup is still NGN based)
        const settings = await SystemSettings.findOne();
        const MARKUP = Number(settings?.globalMarkup || 0);
        const finalAmountNGN = Math.round(Number(amountNGN) + MARKUP);

        const tx_ref = `TOPUP-${Date.now()}-${decoded.id.slice(-4)}`;

        // Initiate Flutterwave Payment
        const response = await fetch("https://api.flutterwave.com/v3/payments", {
            method: "POST",
            headers: {
                Authorization: `Bearer ${process.env.FLW_SECRET_KEY}`,
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                tx_ref,
                amount: finalAmountNGN,
                currency: "NGN",
                redirect_url: "https://www.smsglobe.net/smsuser/topup.html",
                customer: { 
                    email: user.email, 
                    name: user.fullName 
                },
                meta: { 
                    userId: user._id.toString(), 
                    type: "WALLET_TOPUP", 
                    amountNGN: finalAmountNGN
                },
                customizations: { 
                    title: "SMSGlobe Wallet Topup", 
                    logo: "https://imgur.com/8YeZgfx.png" 
                }
            }),
        });

        const data = await response.json();
        if (data.status !== "success") throw new Error(data.message);

        return res.json({ success: true, link: data.data.link });

    } catch (err) {
        console.error("Topup Init Error:", err);
        return res.status(500).json({ success: false, message: "Could not initiate payment" });
    }
}

// --- Updated Verify Topup (NGN Only) ---
async function handleVerifyTopup(req, res) {
    const { transactionId } = req.body;

    if (!transactionId) {
        return res.status(400).json({ success: false, message: "Transaction ID is required" });
    }

    // Use a session to ensure Atomic updates (Both balance and transaction record must save)
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
        const response = await fetch(`https://api.flutterwave.com/v3/transactions/${transactionId}/verify`, {
            method: "GET",
            headers: { 
                Authorization: `Bearer ${process.env.FLW_SECRET_KEY}`,
                "Content-Type": "application/json"
            },
        });

        const flwData = await response.json();

        if (!flwData || flwData.status !== "success") {
            await session.abortTransaction();
            return res.status(400).json({ success: false, message: "Gateway verification failed" });
        }

        const flwStatus = flwData.data.status; 
        const txRef = flwData.data.tx_ref;
        const flwAmountNGN = Number(flwData.data.amount);

        // 1. Check if this reference has already been successfully processed
        const existingTx = await Transaction.findOne({ reference: txRef });
        if (existingTx && existingTx.status === 'successful') {
            await session.abortTransaction();
            return res.json({ 
                success: true, 
                newBalance: existingTx.balanceAfter,
                message: "Transaction already processed." 
            });
        }

        if (flwStatus === "successful") {
            // CRITICAL: Extract userId from meta. Use flwData.data.meta.userId 
            const userId = flwData.data.meta?.userId;
            
            if (!userId) {
                throw new Error("User ID missing from transaction metadata");
            }

            const user = await User.findById(userId).session(session);
            if (!user) throw new Error("User record not found");

            const balanceBefore = Number(user.balance || 0);
            const balanceAfter = balanceBefore + flwAmountNGN;

            // 2. Update/Create Transaction Record
            await Transaction.findOneAndUpdate(
                { reference: txRef },
                {
                    userId: user._id,
                    type: 'credit',
                    purpose: 'deposit',
                    amountNGN: flwAmountNGN,
                    status: 'successful',
                    paymentMethod: flwData.data.payment_type || 'card',
                    balanceBefore,
                    balanceAfter,
                    metadata: flwData.data
                },
                { upsert: true, session }
            );

            // 3. Update User Balance
            user.balance = balanceAfter;
            await user.save({ session });

            // Commit the changes to DB
            await session.commitTransaction();
            session.endSession();

            return res.json({ 
                success: true, 
                amountNGN: flwAmountNGN,
                newBalance: balanceAfter, 
                message: "Wallet funded successfully!" 
            });
        }

        // Handle Pending/Failed statuses
        const finalStatus = flwStatus === "pending" ? "pending" : "failed";
        await Transaction.findOneAndUpdate(
            { reference: txRef },
            { status: finalStatus, metadata: flwData.data },
            { upsert: true, session }
        );

        await session.commitTransaction();
        session.endSession();

        return res.json({ 
            success: (finalStatus === 'pending'), 
            status: finalStatus, 
            message: `Transaction ${finalStatus}.` 
        });

    } catch (err) {
        await session.abortTransaction();
        session.endSession();
        console.error("VERIFICATION ERROR:", err.message);
        return res.status(500).json({ success: false, message: err.message || "Internal server error" });
    }
}

async function handlePurchaseWithWallet(req, res) {
    const { 
        vpnId, proxyId, rdpId, carrierName, 
        mobileNumber, planAmount, planIndex, 
        metadata, planName 
    } = req.body;
    
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    try {
        if (!token) return res.status(401).json({ success: false, message: "Unauthorized" });
        
        const decoded = jwt.verify(token, JWT_SECRET);
        
        // 1. FETCH FRESH USER DATA
        const user = await User.findById(decoded.id);
        if (!user) return res.status(404).json({ success: false, message: "User not found" });

        // 2. IDEMPOTENCY CHECK (Prevents double-charging within 20 seconds)
        const recentOrder = await Order.findOne({
            userId: user._id,
            createdAt: { $gt: new Date(Date.now() - 20000) } 
        });
        if (recentOrder) {
            return res.status(429).json({ success: false, message: "Duplicate request detected. Please wait 20 seconds." });
        }

        let itemType;
        let costNGN = 0;
        let productDetails = { name: "", plan: "" };
        let orderSpecifics = {};

        // 3. PRODUCT LOGIC & STOCK MANAGEMENT
        if (vpnId) {
            const item = await VPN.findOneAndUpdate(
                { _id: vpnId, stock: { $gt: 0 } },
                { $inc: { stock: -1 } },
                { new: true, select: '+password +pcPassword +activationCode' }
            );
            
            if (!item || !item.plans[planIndex]) {
                return res.status(404).json({ success: false, message: "VPN unavailable or out of stock" });
            }

            itemType = "VPN";
            costNGN = Math.round(Number(item.plans[planIndex].price));
            productDetails.name = item.name;
            productDetails.plan = item.plans[planIndex].duration;
            
            orderSpecifics = {
                username: item.username || null,
                password: item.password || null,
                pcUsername: item.pcUsername || null,
                pcPassword: item.pcPassword || null,
                activationCode: item.activationCode || null,
                pcMethod: item.pcMethod || null,
                instructions: item.instructions || "Follow the setup guide provided in your dashboard."
            };
        } 
        else if (proxyId) {
            const item = await Proxy.findOneAndUpdate(
                { _id: proxyId, stock: { $gt: 0 } },
                { $inc: { stock: -1 } },
                { new: true, select: '+activationCode +instructions' } 
            );

            if (!item || !item.plans[planIndex]) {
                return res.status(404).json({ success: false, message: "Proxy unavailable or out of stock" });
            }
            
            itemType = "Proxy";
            costNGN = Math.round(Number(item.plans[planIndex].price));
            productDetails.name = item.name;
            productDetails.plan = `${item.plans[planIndex].ip_count} IPs`;    
            orderSpecifics.activationCode = item.activationCode;
            orderSpecifics.instructions = item.instructions;
        }
        else if (rdpId) {
            itemType = "RDP";
            const rdpPlans = {
                tier1: { id: "tier1", name: "USA Tier 1", price: 45000, ram: "4GB", cpu: "2 Cores", storage: "60GB SSD", net: "1Gbps" },
                tier2: { id: "tier2", name: "USA Tier 2", price: 55000, ram: "6GB", cpu: "3 Cores", storage: "100GB SSD", net: "1Gbps" },
                tier3: { id: "tier3", name: "USA Tier 3", price: 65000, ram: "8GB", cpu: "4 Cores", storage: "140GB SSD", net: "1Gbps" },
                tier4: { id: "tier4", name: "USA Tier 4", price: 80000, ram: "12GB", cpu: "6 Cores", storage: "180GB SSD", net: "2Gbps" },
                tier5: { id: "tier5", name: "USA Tier 5", price: 90000, ram: "18GB", cpu: "8 Cores", storage: "240GB SSD", net: "2Gbps" },
                tier6: { id: "tier6", name: "USA Tier 6", price: 130000, ram: "24GB", cpu: "8 Cores", storage: "280GB SSD", net: "2Gbps" }
            };

            const selectedTier = rdpPlans[rdpId];
            if (!selectedTier) return res.status(404).json({ success: false, message: "RDP Plan not found" });

            const extraCPUCount = parseInt(metadata?.extraCPU || 0);
            const extraStorageGB = parseInt(metadata?.extraStorage || 0);

            costNGN = Math.round(
                Number(selectedTier.price) + 
                (extraCPUCount * 5000) + 
                (extraStorageGB * 2000)
            );
            
            productDetails.name = selectedTier.name;
            productDetails.plan = `${selectedTier.ram} RAM | ${metadata?.osChoice || 'Windows Server'}`;
            
            orderSpecifics = {
                ram: selectedTier.ram,
                cpu: selectedTier.cpu,
                storage: selectedTier.storage,
                net: selectedTier.net,
                os: metadata?.osChoice || "Windows Server",
                extraCPU: extraCPUCount,
                extraStorage: extraStorageGB
            };
        }

       // --- 4. BALANCE VALIDATION (UPDATED FOR USER CHOICE) ---
        const { useBonus } = req.body; // New field from frontend toggle
        const mainBal = Number(user.balance || 0);
        const bonusBal = Number(user.bonusBalance || 0);
        const isBonusUnlocked = user.hasDeposited || mainBal > 0;
        const canUseBonus = useBonus === true && isBonusUnlocked && bonusBal > 0;        
        const buyingPower = canUseBonus ? (mainBal + bonusBal) : mainBal;

        if (buyingPower < costNGN) {
            // Revert stock
            if (vpnId) await VPN.findByIdAndUpdate(vpnId, { $inc: { stock: 1 } });
            if (proxyId) await Proxy.findByIdAndUpdate(proxyId, { $inc: { stock: 1 } });

            let errorMsg = `Insufficient Funds. Required: ₦${costNGN.toLocaleString()}.`;
            if (!useBonus && (mainBal + bonusBal) >= costNGN) {
                errorMsg += " (Try enabling your Bonus Balance to complete this purchase)";
            } else if (!isBonusUnlocked && bonusBal > 0) {
                errorMsg += " (Bonus locked. Deposit to unlock)";
            }

            return res.status(400).json({ success: false, message: errorMsg });
        }
        let remainingToPay = costNGN;
        let bonusDeduction = 0;
        let mainDeduction = 0;

        if (canUseBonus) {
            if (bonusBal >= remainingToPay) {
                bonusDeduction = remainingToPay;
                remainingToPay = 0;
            } else {
                bonusDeduction = bonusBal;
                remainingToPay -= bonusBal;
            }
        }

        if (remainingToPay > 0) {
            mainDeduction = remainingToPay;
        }
       const updatedUser = await User.findOneAndUpdate(
    { 
        _id: user._id, 
        balance: { $gte: mainDeduction } 
    },
    { 
        $inc: { 
            balance: -mainDeduction, 
            bonusBalance: -bonusDeduction 
        } 
    },
    { new: true }
);

        if (!updatedUser) {
            if (vpnId) await VPN.findByIdAndUpdate(vpnId, { $inc: { stock: 1 } });
            if (proxyId) await Proxy.findByIdAndUpdate(proxyId, { $inc: { stock: 1 } });
            
            return res.status(400).json({ 
                success: false, 
                message: "Transaction failed. Please ensure you have sufficient funds and try again." 
            });
        }

        newMainBalance = updatedUser.balance;
        newBonusBalance = updatedUser.bonusBalance;

        const balanceBefore = mainBal; // For Transaction log
        const balanceAfter = updatedUser.balance;
        const paymentReference = `WAL-${Date.now()}-${user._id.toString().slice(-4)}`;

        const newOrder = await Order.create({
            userId: user._id,
            userEmail: user.email,
            fullName: user.fullName,
            productType: itemType,
            planName: productDetails.plan,
            nodeName: productDetails.name,
            targetNumber: mobileNumber || null,
            amount: costNGN, // Total cost
            mainBalanceUsed: mainBal - newMainBalance, // Record specific amount from main
            bonusBalanceUsed: bonusBal - newBonusBalance, // Record specific amount from bonus
            currency: "NGN",
            status: "successful",
            paymentReference: paymentReference,
            metadata: metadata, 
            ...orderSpecifics   
        });

        // 7. CREATE TRANSACTION LOG
        await Transaction.create({
            userId: user._id,
            type: 'debit',
            purpose: 'purchase',
            amountNGN: costNGN,
            status: 'successful',
            reference: paymentReference,
            paymentMethod: 'wallet_combined',            
            balanceBefore: mainBal,
            balanceAfter: newMainBalance,
            bonusBefore: bonusBal,
            bonusAfter: newBonusBalance,
            metadata: { 
                orderId: newOrder._id, 
                product: productDetails.name,
                breakdown: {
                    mainWallet: mainBal - newMainBalance,
                    bonusWallet: bonusBal - newBonusBalance
                },
                extras: itemType === "RDP" ? { 
                    cpu: orderSpecifics.extraCPU, 
                    storage: orderSpecifics.extraStorage 
                } : null
            }
        });

        // 8. SEND DELIVERY EMAIL
        sendDeliveryEmail(user.email, { 
            ...orderSpecifics, 
            amount: `₦${costNGN.toLocaleString()}`,
            planName: productDetails.plan
        }, newOrder).catch(err => console.error("Email Error:", err.message));

        // 9. FINAL RESPONSE
        return res.json({ 
            success: true, 
            message: "Purchase successful!", 
            balance: balanceAfter,
            bonusBalance: updatedUser.bonusBalance,
            order: newOrder,
            rdpDetails: itemType === "RDP" ? {
                ram: newOrder.ram,
                cpu: newOrder.cpu,
                extraCPU: newOrder.extraCPU,
                storage: newOrder.storage,
                extraStorage: newOrder.extraStorage,
                net: newOrder.net,
                os: newOrder.os
            } : null,
            credentials: {
                username: orderSpecifics.username || null,
                password: orderSpecifics.password || null,
                pcUsername: orderSpecifics.pcUsername || null,
                pcPassword: orderSpecifics.pcPassword || null,
                activationCode: orderSpecifics.activationCode || null,
                instructions: orderSpecifics.instructions || null
            }
        });
    } catch (err) {
        console.error("Wallet Purchase Error:", err);
        return res.status(500).json({ success: false, message: "Internal server error." });
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
        headerTitle = "VPN Activated!";
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
    
    let dataTableHtml = '';

    if (isRDP) {
        const specsString = credentials.specs || ""; 
        const specParts = specsString.split(',').map(s => s.trim());
        const ramValue = credentials.ram || specParts[0] || '4GB RAM';
        const cpuValue = credentials.cpu || specParts[1] || '2 Cores';
        const storageValue = credentials.storage || specParts[2] || '60GB SSD';

        dataTableHtml = `
            <tr>
                <td class="mobile-full" width="50%" valign="top" style="padding-bottom: 15px;">
                    <span style="font-size: 9px; color: #667085; text-transform: uppercase; font-weight: bold;">Login Details (IP/User/Pass)</span><br>
                    <strong style="font-size: 13px; font-family: 'Courier New', monospace; color: #0F54C6;">${credentials.confirmationNumber || 'Details in Dashboard'}</strong>
                </td>
                <td class="mobile-full" width="50%" valign="top" style="text-align: right; padding-bottom: 15px;">
                    <span style="font-size: 9px; color: #667085; text-transform: uppercase; font-weight: bold;">Operating System</span><br>
                    <strong style="font-size: 13px; color: #101828;">${credentials.osChoice || 'Windows Server'}</strong>
                </td>
            </tr>
            <tr>
                <td class="mobile-full" width="33%" valign="top">
                    <span style="font-size: 9px; color: #667085; text-transform: uppercase; font-weight: bold;">RAM</span><br>
                    <strong style="font-size: 12px; color: #101828;">${ramValue}</strong>
                </td>
                <td class="mobile-full" width="33%" valign="top" style="text-align: center;">
                    <span style="font-size: 9px; color: #667085; text-transform: uppercase; font-weight: bold;">CPU</span><br>
                    <strong style="font-size: 12px; color: #101828;">${cpuValue}</strong>
                </td>
                <td class="mobile-full" width="33%" valign="top" style="text-align: right;">
                    <span style="font-size: 9px; color: #667085; text-transform: uppercase; font-weight: bold;">Storage</span><br>
                    <strong style="font-size: 12px; color: #101828;">${storageValue}</strong>
                </td>
            </tr>`;
  } else if (productType === "VPN") { // Using your productType variable
    const hasMobile = !!credentials.username;
    const hasPC = !!credentials.pcUsername;
    const hasCode = !!credentials.activationCode;

    dataTableHtml = `
        <tr>
            <td colspan="2" valign="top" style="padding-bottom: 20px;">
                <div style="background: #f9fafb; border: 1px solid #eaecf0; padding: 12px; border-radius: 8px; text-align: center;">
                    <span style="font-size: 10px; color: #667085; text-transform: uppercase; font-weight: 800; letter-spacing: 0.5px;">Connection Limit</span><br>
                    <strong style="font-size: 15px; color: #0F54C6;">${credentials.deviceLimit || 1} Device(s) Allowed</strong>
                </div>
            </td>
        </tr>

        ${hasMobile ? `
        <tr>
            <td width="50%" valign="top" style="padding-bottom: 15px;">
                <span style="font-size: 9px; color: #667085; text-transform: uppercase; font-weight: bold;">Mobile/Email User</span><br>
                <strong style="font-size: 12px; font-family: 'Courier New', monospace; color: #101828;">${credentials.username}</strong>
            </td>
            <td width="50%" valign="top" style="text-align: right; padding-bottom: 15px;">
                <span style="font-size: 9px; color: #667085; text-transform: uppercase; font-weight: bold;">Mobile Password</span><br>
                <strong style="font-size: 12px; font-family: 'Courier New', monospace; color: #0F54C6;">${credentials.password}</strong>
            </td>
        </tr>` : ''}

        ${hasPC ? `
        <tr>
            <td width="50%" valign="top" style="padding-bottom: 15px; border-top: 1px solid #f2f4f7; padding-top: 10px;">
                <span style="font-size: 9px; color: #667085; text-transform: uppercase; font-weight: bold;">PC Username</span><br>
                <strong style="font-size: 12px; font-family: 'Courier New', monospace; color: #101828;">${credentials.pcUsername}</strong>
            </td>
            <td width="50%" valign="top" style="text-align: right; padding-bottom: 15px; border-top: 1px solid #f2f4f7; padding-top: 10px;">
                <span style="font-size: 9px; color: #667085; text-transform: uppercase; font-weight: bold;">PC Password</span><br>
                <strong style="font-size: 12px; font-family: 'Courier New', monospace; color: #0F54C6;">${credentials.pcPassword}</strong>
            </td>
        </tr>` : ''}

        ${hasCode ? `
        <tr>
            <td colspan="2" valign="top" style="padding: 15px; background-color: #f0f5ff; border-radius: 8px; margin-bottom: 15px;">
                <span style="font-size: 9px; color: #0F54C6; text-transform: uppercase; font-weight: bold;">Activation Code ${credentials.pcMethod ? `(${credentials.pcMethod})` : ''}</span><br>
                <strong style="font-size: 16px; font-family: 'Courier New', monospace; color: #101828; letter-spacing: 1px;">${credentials.activationCode}</strong>
            </td>
        </tr>` : ''}

        <tr>
            <td colspan="2" style="border-top: 1px solid #D1E0FF; padding-top: 15px;">
                <span style="font-size: 9px; color: #667085; text-transform: uppercase; font-weight: bold;">How to Setup</span><br>
                <p style="font-size: 12px; color: #344054; line-height: 1.6; margin: 5px 0;">
                    ${credentials.instructions || 'Login to your SMSGlobe dashboard to download the specific apps for your device.'}
                </p>
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
                    <strong style="font-size: 13px; color: #101828;">${credentials.nodeName || credentials.carrierName || 'Global eSIM'}</strong>
                </td>
            </tr>
            <tr>
                <td class="mobile-full" width="50%" valign="top" style="padding-bottom: 15px;">
                    <span style="font-size: 9px; color: #667085; text-transform: uppercase; font-weight: bold;">Device Model</span><br>
                    <strong style="font-size: 12px; color: #344054;">${credentials.mobileNumber || credentials.deviceModel || 'Compatible Device'}</strong>
                </td>
                <td class="mobile-full" width="50%" valign="top" style="text-align: right; padding-bottom: 15px;">
                    <span style="font-size: 9px; color: #667085; text-transform: uppercase; font-weight: bold;">Amount Paid</span><br>
                    <strong style="font-size: 13px; color: #101828;">₦${credentials.amount || '0'}</strong>
                </td>
            </tr>`;
    } else if (isESIM_Refill) {
        dataTableHtml = `
            <tr>
                <td class="mobile-full" width="50%" valign="top" style="padding-bottom: 15px;">
                    <span style="font-size: 9px; color: #667085; text-transform: uppercase; font-weight: bold;">Carrier</span><br>
                    <strong style="font-size: 13px; color: #0F54C6;">${credentials.nodeName || credentials.carrierName}</strong>
                </td>
                <td class="mobile-full" width="50%" valign="top" style="text-align: right; padding-bottom: 15px;">
                    <span style="font-size: 9px; color: #667085; text-transform: uppercase; font-weight: bold;">Mobile Number</span><br>
                    <strong style="font-size: 13px; font-family: 'Courier New', monospace; color: #101828;">${credentials.targetNumber || credentials.mobileNumber}</strong>
                </td>
            </tr>
            <tr>
                <td class="mobile-full" width="50%" valign="top">
                    <span style="font-size: 9px; color: #667085; text-transform: uppercase; font-weight: bold;">Refill Plan</span><br>
                    <strong style="font-size: 13px; color: #101828;">${credentials.planName || credentials.amount}</strong>
                </td>
                <td class="mobile-full" width="50%" valign="top" style="text-align: right;">
                    <span style="font-size: 9px; color: #667085; text-transform: uppercase; font-weight: bold;">Reference #</span><br>
                    <strong style="font-size: 13px; font-family: 'Courier New', monospace; color: #F9861E;">${credentials.confirmationNumber || 'PROCESSING'}</strong>
                </td>
            </tr>`;
    } else {
        dataTableHtml = `
            <tr>
                <td class="mobile-full" width="50%" valign="top" style="padding-bottom: 10px;">
                    <span style="font-size: 9px; color: #667085; text-transform: uppercase; font-weight: bold;">ID / Code</span><br>
                    <strong style="font-size: 14px; font-family: 'Courier New', monospace; color: #0F54C6;">
                        ${credentials.activationCode || credentials.confirmationNumber || 'N/A'}
                    </strong>
                </td>
                <td class="mobile-full" width="50%" valign="top" style="text-align: right; padding-bottom: 10px;">
                    <span style="font-size: 9px; color: #667085; text-transform: uppercase; font-weight: bold;">Price Paid</span><br>
                    <strong style="font-size: 14px; color: #101828;">₦${credentials.amount}</strong>
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
                                Hello, thank you for choosing <strong>SMSGlobe</strong>. Your service details are provided below.
                            </p>
                            <div style="background: #F0F5FE; padding: 20px; border-radius: 12px; border: 1px solid #D1E0FF; margin-bottom: 24px;">
                                <p style="margin: 0 0 10px 0; font-size: 10px; color: #0F54C6; font-weight: 800; text-transform: uppercase;">Service Order Info</p>
                                <table border="0" cellpadding="0" cellspacing="0" width="100%">
                                    ${dataTableHtml}
                                </table>
                            </div>
                            <div style="text-align: center; margin-top: 30px;">
                                <a href="https://smsglobe.net" style="background-color: #0F54C6; color: #ffffff; padding: 12px 24px; text-decoration: none; font-size: 13px; font-weight: bold; border-radius: 8px; display: inline-block;">Access Dashboard</a>
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

const sendResetPasswordEmail = async (userEmail, resetLink, isAdmin = false) => {
    const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASS
        }
    });

    // Dynamic content based on account type
    const accountType = isAdmin ? "Admin Control Panel" : "User Account";
    const subject = isAdmin ? "🔐 Urgent: Admin Password Reset" : "🔐 Reset Your SMSGlobe Password";
    const headerTitle = isAdmin ? "Admin Security Update" : "Password Reset Request";
    const subHeader = `Security credentials for your ${accountType} are being updated.`;

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

                        <div style="background-color: ${isAdmin ? '#101828' : '#0F54C6'}; color: white; padding: 35px 24px; text-align: center;">
                            <h2 style="margin: 0; font-size: 22px;">${headerTitle}</h2>
                            <p style="opacity: 0.8; font-size: 13px; margin-top: 8px;">${subHeader}</p>
                        </div>

                        <div style="padding: 24px; color: #344054; text-align: left;">
                            <p style="font-size: 14px; line-height: 1.5; margin-bottom: 24px;">
                                Hello, a request was made to reset the password for the <strong>${accountType}</strong> associated with this email. Click the button below to proceed. <strong>This link is valid for 1 hour.</strong>
                            </p>
                            
                            <div style="background: #F0F5FE; padding: 20px; border-radius: 12px; border: 1px solid #D1E0FF; margin-bottom: 24px; text-align: center;">
                                <p style="margin: 0 0 10px 0; font-size: 10px; color: #0F54C6; font-weight: 800; text-transform: uppercase;">Security Action Required</p>
                                
                                <div style="margin: 20px 0;">
                                    <a href="${resetLink}" style="background-color: #0F54C6; color: #ffffff; padding: 14px 30px; text-decoration: none; font-size: 14px; font-weight: bold; border-radius: 8px; display: inline-block; shadow: 0 4px 6px -1px rgba(15, 84, 198, 0.2);">
                                        Reset ${isAdmin ? 'Admin' : 'My'} Password
                                    </a>
                                </div>
                            </div>

                            <p style="font-size: 12px; color: #667085;">
                                If you did not request this, please contact technical support immediately.
                            </p>
                        </div>

                        <div style="background: #F9FAFB; padding: 20px; text-align: center; border-top: 1px solid #EAECF0;">
                            <p style="font-size: 11px; color: #667085; margin: 0;">&copy; 2026 <strong>SMSGlobe</strong>. Secure Digital Services.</p>
                        </div>
                    </div>
                </td>
            </tr>
        </table>
    </body>
    </html>`;

    await transporter.sendMail({
        from: `"SMSGlobe Security" <${process.env.EMAIL_USER}>`,
        to: userEmail,
        subject: subject,
        html: htmlContent
    });
};

// 2. GET ALL Proxies (Sorted by Newest)
async function handleGetProxies(req, res) {
    try {
        const proxies = await Proxy.find({}).sort({ createdAt: -1 });
        // Returns the list directly with NGN prices as stored in DB
        return res.json({ success: true, proxies });
    } catch (err) {
        return res.status(500).json({ success: false, message: "Fetch failed" });
    }
}

// 3. ADD Proxy (Cleaned for NGN)
async function handleAddProxy(req, res) {
    try {
        const { name, category, imageUrl, activationCode, instructions, plans, stock } = req.body;

        // Clean and parse the plans - Ensuring prices are rounded NGN
        let formattedPlans = [];
        if (plans && Array.isArray(plans)) {
            formattedPlans = plans.map(p => ({
                ip_count: parseInt(p.ip_count) || 0,
                // Math.round ensures we don't store weird floating point decimals
                price: Math.round(parseFloat(p.price)) || 0 
            }));
        }

        const newProxy = new Proxy({
            name,
            category: category || 'Standard', 
            imageUrl,
            activationCode,
            instructions,
            stock: parseInt(stock) || 0,
            plans: formattedPlans
        });

        await newProxy.save();
        return res.json({ success: true, message: "Proxy Package Deployed Successfully in NGN" });
    } catch (err) {
        console.error("Add Proxy Error:", err);
        return res.status(500).json({ success: false, message: "Deployment failed" });
    }
}

// 4. UPDATE Proxy (Cleaned for NGN)
async function handleUpdateProxy(req, res) {
    try {
        const { proxyId, plans, stock, ...restOfData } = req.body;

        const updatePayload = { 
            ...restOfData,
            stock: parseInt(stock) || 0 
        };

        // Handle plans parsing specifically for NGN
        if (plans && Array.isArray(plans)) {
            updatePayload.plans = plans.map(p => ({
                ip_count: parseInt(p.ip_count) || 0,
                price: Math.round(parseFloat(p.price)) || 0 
            }));
        }

        const updated = await Proxy.findByIdAndUpdate(
            proxyId, 
            { $set: updatePayload }, 
            { new: true }
        );
        
        if (!updated) return res.status(404).json({ success: false, message: "Proxy not found" });

        return res.json({ success: true, message: "Proxy Package Updated (NGN)" });
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

    // Validation
    if (!email || !carrierName || !mobileNumber || !planAmount) {
        return res.status(400).json({ success: false, message: "Missing required eSIM data" });
    }

    try {
        // --- NEW: FETCH DYNAMIC SETTINGS FROM DB ---
        const settings = await SystemSettings.findOne();
        const LIVE_RATE = settings?.exchangeRate || 1380; 
        const MARKUP = settings?.globalMarkup || 0; 
        // --------------------------------------------

        // 1. Clean the USD amount (e.g., "$15.00" -> 15)
        const amountUSD = parseFloat(planAmount.replace(/[$,]/g, ''));
        
        // 2. Calculate the Naira equivalent + Markup
        const basePriceNGN = amountUSD * LIVE_RATE;
        const markupAmount = basePriceNGN * (MARKUP / 100);
        const finalAmountNGN = Math.round(basePriceNGN + markupAmount);

        // 3. Create the order using your existing Order model
        const newOrder = await Order.create({
            userEmail: email,
            productType: 'eSIM',
            nodeName: carrierName,      // Mapping Carrier to nodeName
            planName: planAmount,       // Mapping Plan to planName
            targetNumber: mobileNumber, // The eSIM phone number
            productImage: productImage, // Carrier logo URL
            amount: finalAmountNGN,     // Saving the DYNAMICALLY calculated Naira amount
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
    
    if (!tid) return res.status(400).json({ success: false, message: "Missing Transaction ID" });

    try {
        const updatedOrder = await Order.findOneAndUpdate(
            { paymentReference: tid, productType: 'eSIM' },
            { $set: { status: 'Completed', updatedAt: new Date() } },
            { new: true }
        );

        if (updatedOrder) {
            try {
                await sendDeliveryEmail(updatedOrder.userEmail, {
                    type: "eSIM_Refill", // Changed to match your Refill block naming
                    nodeName: updatedOrder.nodeName || "eSIM Carrier",
                    targetNumber: updatedOrder.targetNumber,
                    amount: `${updatedOrder.currency} ${updatedOrder.amount}`,
                    instructions: "Your refill has been processed successfully. Please check your device balance."
                });
            } catch (err) { 
                console.error("Email error:", err); 
            }

            // RETURN JSON INSTEAD OF HTML STRINGS
            return res.json({ 
                success: true, 
                message: "eSIM Refill Confirmed", 
                order: updatedOrder 
            });
        } else {
            return res.status(404).json({ success: false, message: "Order not found" });
        }
    } catch (error) {
        console.error("Refill Error:", error);
        return res.status(500).json({ success: false, message: "Internal Server Error" });
    }
}

// BACKEND: handleAdminEsimUpdate
async function handleAdminEsimUpdate(req, res) {
    // 1. Get Tid from query or body (consistency is key)
    const tid = req.query.tid || req.body.tid;
    const { confirmationNumber } = req.body;

    if (!tid) return res.status(400).json({ success: false, message: "TID is required" });

    try {
        // 2. IMPORTANT: Check your productType. Is it 'eSIM' or 'eSIM_Refill'?
        // Using an array $in covers both possibilities.
        const updatedOrder = await Order.findOneAndUpdate(
            { 
                paymentReference: tid, 
                productType: { $in: ['eSIM', 'eSIM_Refill'] } 
            },
            { 
                $set: { 
                    status: 'Completed', 
                    confirmationNumber: confirmationNumber, 
                    updatedAt: new Date() 
                } 
            },
            { new: true }
        );

        // 3. If no order found, return 404 JSON (NOT an HTML string)
        if (!updatedOrder) {
            console.error(`Order with TID ${tid} not found.`);
            return res.status(404).json({ success: false, message: "Order record not found." });
        }

        // 4. Trigger Email (Wrapped in try/catch so it doesn't crash the main process)
        try {
            await sendDeliveryEmail(updatedOrder.userEmail, {
                type: "eSIM_Refill",
                nodeName: updatedOrder.nodeName || "Carrier",
                targetNumber: updatedOrder.targetNumber,
                amount: `${updatedOrder.currency} ${updatedOrder.amount}`,
                activationCode: confirmationNumber || updatedOrder.confirmationNumber,
                confirmationNumber: confirmationNumber,
                instructions: "Your refill is now active."
            });
        } catch (emailErr) {
            console.error("Email failed but order was saved:", emailErr.message);
        }

        // 5. Always return JSON
        return res.json({ success: true, message: "Refill marked as completed." });

    } catch (error) {
        console.error("CRITICAL BACKEND ERROR:", error);
        return res.status(500).json({ success: false, message: "Internal Server Error", error: error.message });
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
            const amountInUSD = refill.amount / 1380;

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
       // 3. Trigger Email for successful activations with CORRECT mapping
        if (isFinished) {
            try {
                // We create the 'credentials' object using the EXACT keys 
                // that your sendDeliveryEmail function expects.
                await sendDeliveryEmail(updatedOrder.userEmail, {
                    type: "eSIM_Activation", // Must match your template check
                    
                    // Display Fields
                    nodeName: updatedOrder.nodeName || "Global eSIM",
                    planName: updatedOrder.planName,
                    amount: `${updatedOrder.currency} ${updatedOrder.amount}`, // Show real price
                    
                    // Metadata Fields (Must match credentials.address, credentials.zip)
                    address: updatedOrder.metadata?.address || "Digital Delivery",
                    zip: updatedOrder.metadata?.zip || "N/A",
                    mobileNumber: updatedOrder.targetNumber || "eSIM Device", // Device Model
                    email: updatedOrder.metadata?.email || updatedOrder.userEmail,
                    
                    // Activation Data
                    activationCode: confirmationNumber || updatedOrder.confirmationNumber,
                    
                    instructions: "Your eSIM activation is complete. Please use the Activation code provided to set up your device."
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
            const amountInUSD = activation.amount / 1380;
            
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
            const nairaAmount = parseFloat(order.amount) || 0;
            const meta = order.metadata || {};
            const rdpDetails = order.rdpDetails || {};

            return {
                paymentReference: order.paymentReference,
                productType: 'RDP',
                createdAt: order.createdAt,
                userEmail: order.userEmail,
                fullName: meta.fullName || 'N/A',
                nodeName: order.nodeName || 'USA Tier 1',
                planName: order.planName || 'RDP Server',
                paymentMethod: order.useBonus ? "Bonus + Main" : "Main Wallet Only",
                bonusDeducted: order.bonusUsed || 0,
                metadata: {
                    osChoice: meta.osChoice || rdpDetails.os || 'Windows',
                    ram: meta.ram || 'Standard',
                    storage: meta.storage || 'Standard',
                    net: order.net || 'N/A',
                    extraCPU: meta.extraCPU || 0,
                    extraStorage: meta.extraStorage || 0
                },
                amount: nairaAmount, 
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
                    'X-API-KEY': process.env.TEXTVERIFIED_V2_KEY,
                    'Accept': 'application/json'
                } 
            }
        );
        
        // V2 returns "token", V1 returned "bearer_token". We check both to be safe.
        const token = response.data.token || response.data.bearer_token;
        
        if (!token) {
            console.error("Auth response received but no token found:", response.data);
        }
        
        return token;
    } catch (err) {
        // This will show you the REAL reason in Vercel Logs (Unauthorized, Invalid Key, etc.)
        console.error("Textverified Auth Failed:", err.response?.data || err.message);
        return null;
    }
}
// --- Updated: Fetch Numbers (Inventory) ---
async function handleGetNumbers(req, res) {
    const { service } = req.query; 

    try {
        const apiKey = process.env.TELLABOT_API_KEY;
        const apiUser = process.env.TELLABOT_USER;

        if (!apiKey || !apiUser) {
            return res.status(500).json({ success: false, message: "Server config missing (API Key or User)." });
        }

        // According to your screenshot, cmd is 'list_services'
        const response = await axios.get('https://www.tellabot.com/api_command.php', {
            params: {
                cmd: 'list_services',
                user: apiUser,
                api_key: apiKey
            }
        });

        // Tell A Bot format: { status: "ok", message: [ {service: "Amazon", price: "0.50"}, ... ] }
        if (response.data.status === 'ok' && Array.isArray(response.data.message)) {
            const services = response.data.message;
            
            // Search by 'service' field from the API response
            const target = services.find(s => 
                s.service && s.service.toLowerCase().includes(service.toLowerCase())
            );

            if (target) {
                return res.json({ 
                    success: true, 
                    numbers: [`Secure ${target.service} Line`], 
                    targetId: target.service, // Tell A Bot 'request' uses the name string
                    cost: target.price,
                    name: target.service
                });
            }
        }

        return res.json({ success: false, message: `Service '${service}' not found or out of stock.` });

    } catch (err) {
        console.error("Tell A Bot Sync Error:", err.message);
        return res.status(500).json({ success: false, message: "Sync Failed: " + err.message });
    }
}

// --- Updated: Handle Stock Mapping ---
async function handleGetStock(req, res) {
    try {
        const apiKey = process.env.TELLABOT_API_KEY;
        const apiUser = process.env.TELLABOT_USER;

        if (!apiKey || !apiUser) return res.json({ success: false, message: "Server config missing" });

        const response = await axios.get('https://www.tellabot.com/api_command.php', {
            params: {
                cmd: 'list_services',
                user: apiUser,
                api_key: apiKey
            }
        });

        const stockData = {};
        if (response.data.status === 'ok' && Array.isArray(response.data.message)) {
            response.data.message.forEach(s => {
                // Map the Service Name (used as ID) to its Price
                stockData[s.service] = s.price; 
            });
        }

        return res.json({ 
            success: true, 
            stock: stockData 
        });
    } catch (err) {
        console.error("Tell A Bot Stock Sync Error:", err.message);
        return res.json({ success: false, stock: {}, message: "Stock sync failed" });
    }
}

// --- Updated: Activate/Purchase Number ---
async function handleActivatePurchase(req, res) {
    const { targetId } = req.body; // This is the service name (e.g., 'WhatsApp')

    try {
        const apiKey = process.env.TELLABOT_API_KEY;
        const apiUser = process.env.TELLABOT_USER;

        const response = await axios.get('https://www.tellabot.com/api_command.php', {
            params: {
                cmd: 'request', 
                user: apiUser,
                api_key: apiKey,
                service: targetId
            }
        });

        // According to your screenshot:
        // Success returns { "status": "ok", "message": [ { "mdn": "15302286946", "id": "10000001", ... } ] }
        if (response.data.status === 'ok' && response.data.message && response.data.message.length > 0) {
            const order = response.data.message[0];
            return res.json({
                success: true,
                rentalId: order.id,
                number: order.mdn, // MDN is the phone number field
                message: "Number Reserved!"
            });
        }

        // Error returns { "status": "error", "message": "Reason here" }
        return res.status(400).json({ 
            success: false, 
            message: response.data.message || "No numbers available or insufficient balance." 
        });

    } catch (err) {
        console.error("Tell A Bot Purchase Error:", err.message);
        return res.status(500).json({ success: false, message: "Purchase failed." });
    }
}

async function handleGetUserOrders(req, res) {
    try {
        // 1. Get the token from headers
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ success: false, message: "Unauthorized" });
        }

        const token = authHeader.split(' ')[1];
        
        const jwt = require('jsonwebtoken');
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your_secret_key');
        const userEmail = decoded.email;

        if (!userEmail) {
            return res.status(400).json({ success: false, message: "Invalid token data" });
        }

        // We use the email to find all orders linked to this account
        const orders = await Order.find({ userEmail: userEmail })
            .sort({ createdAt: -1 }) // Newest first
            .lean(); // Faster performance for read-only

        // 4. Return the orders
        return res.json(orders);

    } catch (err) {
        console.error("Error fetching user orders:", err);
        
        if (err.name === 'JsonWebTokenError') {
            return res.status(401).json({ success: false, message: "Invalid Session" });
        }

        return res.status(500).json({ 
            success: false, 
            message: "Failed to retrieve order history" 
        });
    }
}

async function handleChangePassword(req, res) {
    try {
        const { oldPass, newPass } = req.body;
        const authHeader = req.headers.authorization;

        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ success: false, message: "Unauthorized" });
        }

        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your_secret_key');
        
        // 1. Find User in DB
        const user = await User.findOne({ email: decoded.email });
        if (!user) {
            return res.status(404).json({ success: false, message: "User not found" });
        }

        // 2. Verify Old Password
        // Note: Replace 'user.password' with whatever field name you use in your Schema
        const isMatch = await bcrypt.compare(oldPass, user.password);
        if (!isMatch) {
            return res.status(400).json({ success: false, message: "Current password is incorrect" });
        }

        // 3. Hash New Password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(newPass, salt);

        // 4. Update Database
        user.password = hashedPassword;
        await user.save();

        return res.json({ 
            success: true, 
            message: "Password updated successfully!" 
        });

    } catch (err) {
        console.error("Password Update Error:", err);
        return res.status(500).json({ 
            success: false, 
            message: "Internal server error" 
        });
    }
}

async function handleResetPassword(req, res) {
    try {
        const { token, newPass } = req.body;

        if (!token || !newPass) {
            return res.status(400).json({ 
                success: false, 
                message: "Missing token or password" 
            });
        }

        // 1. Find user by reset token and ensure it hasn't expired
        // This assumes your User schema has: resetPasswordToken and resetPasswordExpires fields
        const user = await User.findOne({
            resetPasswordToken: token,
            resetPasswordExpires: { $gt: Date.now() } // Check if token is still valid
        });

        if (!user) {
            return res.status(400).json({ 
                success: false, 
                message: "Invalid or expired reset token" 
            });
        }

        // 2. Hash the New Password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(newPass, salt);

        // 3. Update User and Clear the Reset Token fields
        user.password = hashedPassword;
        user.resetPasswordToken = undefined; // Clear token after use
        user.resetPasswordExpires = undefined; // Clear expiry after use
        await user.save();

        // 4. Generate a fresh Session Token (JWT) 
        // This ensures the user is logged in immediately after the reset
        const sessionToken = jwt.sign(
            { email: user.email, id: user._id }, 
            process.env.JWT_SECRET || 'your_secret_key', 
            { expiresIn: '1d' }
        );

        return res.json({ 
            success: true, 
            message: "Password reset successful!",
            token: sessionToken // Frontend will save this to localStorage
        });

    } catch (err) {
        console.error("Reset Password Error:", err);
        return res.status(500).json({ 
            success: false, 
            message: "Internal server error" 
        });
    }
}

async function handleForgotPasswordRequest(req, res) {
    try {
        const { email } = req.body;
        if (!email) return res.status(400).json({ success: false, message: "Email required" });

const user = await User.findOne({ email: email.toLowerCase().trim() }).select('+password');
        if (!user) {
            return res.json({ success: true, message: "If an account exists, a reset link has been sent." });
        }
        const token = crypto.randomBytes(32).toString('hex');
        user.resetPasswordToken = token;
        user.resetPasswordExpires = Date.now() + 3600000; 
        await user.save();
        const resetLink = `https://smsglobe.net/smsuser/change-password.html?token=${token}`;
    await sendResetPasswordEmail(user.email, resetLink);
        console.log("Reset link for testing:", resetLink);
        return res.json({ 
            success: true, 
            message: "A password reset link has been sent to your email." 
        });

    } catch (err) {
        console.error("Forgot Password Error:", err);
        return res.status(500).json({ success: false, message: "Internal server error" });
    }
}

async function handleAdminChangePassword(req, res) {
    try {
        const { oldPassword, newPassword } = req.body;
        const authHeader = req.headers.authorization;

        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ success: false, message: "Unauthorized" });
        }

        const token = authHeader.split(' ')[1];
        let decoded;
        
        try {
            decoded = jwt.verify(token, process.env.JWT_SECRET || 'your_secret_key');
        } catch (jwtErr) {
            return res.status(401).json({ success: false, message: "Session expired" });
        }

        if (!oldPassword || !newPassword) {
            return res.status(400).json({ success: false, message: "Missing required fields" });
        }

        const admin = await Admin.findOne({ email: decoded.email }) || await Admin.findById(decoded.id);

        if (!admin) {
            return res.status(404).json({ success: false, message: "Admin account not found" });
        }

        const isMatch = await bcrypt.compare(oldPassword, admin.password);
        if (!isMatch) {
            return res.status(401).json({ success: false, message: "Current password incorrect" });
        }

        const salt = await bcrypt.genSalt(10);
        admin.password = await bcrypt.hash(newPassword, salt);
        await admin.save();

        return res.json({ success: true, message: "Admin password updated successfully!" });

    } catch (error) {
        console.error("Admin Password Error:", error);
        return res.status(500).json({ success: false, message: "Internal server error" });
    }
}

async function handleAdminForgotPasswordRequest(req, res) {
    try {
        const { email } = req.body;
        if (!email) return res.status(400).json({ success: false, message: "Email required" });

        // Search the Admin collection specifically
        const admin = await Admin.findOne({ email: email.toLowerCase().trim() });

        // Security: Same response whether admin exists or not
        if (!admin) {
            return res.json({ 
                success: true, 
                message: "If an account exists, a reset link has been sent." 
            });
        }

        // 1. Generate a secure token
        const token = crypto.randomBytes(32).toString('hex');

        // 2. Set token and expiry on the ADMIN record (1 hour)
        admin.resetPasswordToken = token;
        admin.resetPasswordExpires = Date.now() + 3600000; 
        await admin.save();

        // 3. Admin-specific reset link
        const resetLink = `https://smsglobe.net/smsadmin/sms_forgot.html?token=${token}`;
        
        // Use your email utility (ensure it's configured for Admin notifications)
        await sendResetPasswordEmail(admin.email, resetLink, true);
        console.log("Admin Reset Link:", resetLink);

        return res.json({ 
            success: true, 
            message: "A password reset link has been sent to your email." 
        });

    } catch (err) {
        console.error("Admin Forgot Password Error:", err);
        return res.status(500).json({ success: false, message: "Internal server error" });
    }
}

async function handleAdminResetPassword(req, res) {
    try {
        const { token, newPassword } = req.body;

        if (!token || !newPassword) {
            return res.status(400).json({ success: false, message: "Invalid request" });
        }

        // Find admin with valid token AND ensure it hasn't expired
        const admin = await Admin.findOne({
            resetPasswordToken: token,
            resetPasswordExpires: { $gt: Date.now() } // $gt means "greater than"
        });

        if (!admin) {
            return res.status(400).json({ 
                success: false, 
                message: "Password reset link is invalid or has expired." 
            });
        }

        // Hash the new password
        const salt = await bcrypt.genSalt(10);
        admin.password = await bcrypt.hash(newPassword, salt);

        // Clear the reset fields so the token can't be used again
        admin.resetPasswordToken = undefined;
        admin.resetPasswordExpires = undefined;
        
        await admin.save();

        return res.json({ success: true, message: "Admin password reset successfully!" });

    } catch (error) {
        console.error("Admin Reset Final Error:", error);
        return res.status(500).json({ success: false, message: "Internal server error" });
    }
}

// 1. GET settings (For Admin Page)
async function handleGetSystemSettings(req, res) {
    try {
        // Use SystemSettings to match your schema variable
        let settings = await SystemSettings.findOne();
        if (!settings) {
            // Create default document if the collection is empty
            settings = await SystemSettings.create({}); 
        }
        res.json({ success: true, settings });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
}

// 2. UPDATE settings (From Admin Page)
async function handleUpdateSystemSettings(req, res) {
    try {
        const updateData = req.body;

        // "upsert: true" is perfect here—it creates the doc if it doesn't exist
        const updated = await SystemSettings.findOneAndUpdate(
            {}, 
            { $set: updateData }, 
            { upsert: true, new: true }
        );

        return res.json({ 
            success: true, 
            message: "System configuration updated.", 
            settings: updated 
        });
    } catch (err) {
        console.error("Settings Update Error:", err);
        return res.status(500).json({ success: false, message: "Server error updating settings." });
    }
}

// 3. PUBLIC status check (For User Frontend / Login Page)
async function handleGetSystemStatus(req, res) {
    try {
        // Added .lean() for faster performance on public pings
        const settings = await SystemSettings.findOne().select('maintenanceMode noticeBar').lean();
        
        res.json({ 
    success: true, 
    maintenanceMode: settings?.maintenanceMode || false,
    noticeBar: settings?.noticeBarText || "" // Ensure this key matches your frontend 'status.noticeBar'
});
    } catch (err) {
        // If the DB fails, we default to false so we don't lock everyone out by accident
        res.json({ success: false, maintenanceMode: false }); 
    }
}

async function handleGetUserTransactions(req, res) {
    try {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];

        if (!token) {
            return res.status(401).json({ success: false, message: "No token provided" });
        }

        const decoded = jwt.verify(token, JWT_SECRET);
        const userId = decoded.id || decoded._id;

        if (!userId) {
            return res.status(401).json({ success: false, message: "Invalid token payload" });
        }
        
        const { type } = req.query;
        let query = { userId: new mongoose.Types.ObjectId(userId) };

        if (type === 'topup') {
            query.purpose = 'deposit';
        }

        const transactions = await Transaction.find(query)
            .sort({ createdAt: -1 })
            .limit(50)
            .lean();

        return res.json({
            success: true,
            transactions: transactions.map(tx => {
                // Determine the source label
                let sourceLabel = 'Main Wallet';
                
                // If it's a purchase and usedBonus is true in metadata
                if (tx.purpose !== 'deposit' && tx.metadata?.usedBonus === true) {
                    sourceLabel = 'Referral Bonus';
                } else if (tx.purpose === 'deposit') {
                    sourceLabel = tx.metadata?.payment_type || 'External Topup';
                }

                return {
                    id: tx._id,
                    amountUSD: tx.amountUSD,
                    amountNGN: tx.amountNGN,
                    status: tx.status,
                    reference: tx.reference,
                    purpose: tx.purpose,
                    createdAt: tx.createdAt,
                    // Use the new sourceLabel here
                    paymentMethod: sourceLabel 
                };
            })
        });
    } catch (error) {
        console.error("CRITICAL_TRANSACTION_ERROR:", error.message);
        return res.status(500).json({ 
            success: false, 
            message: "Internal Server Error",
            error: error.message 
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