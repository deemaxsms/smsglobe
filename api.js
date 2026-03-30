const express = require('express');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const path = require('path');
const { OAuth2Client } = require('google-auth-library');
const nodemailer = require('nodemailer');


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

const orderSchema = new mongoose.Schema({
    userEmail: { type: String, required: true, index: true },
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    fullName: { type: String },         
    productType: { 
        type: String, 
        enum: ['VPN', 'Proxy', 'eSIM', 'eSIM_Refill'], 
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
    paymentReference: { type: String, unique: true },
    activationCode: String, 
    vpnCredentials: {
        username: String,
        password: { type: String }
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
    
    // Normalize the action string to avoid hidden spaces or casing issues
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
    // Added carrierName, mobileNumber, and planAmount for eSIM
    const { vpnId, proxyId, carrierName, mobileNumber, planAmount, planIndex } = req.body;
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
        let amountInUSD;
        let redirectUrl = "https://smsglobe.vercel.app/smsuser/user_dashboard.html"; // Default

        // 1. Logic for VPN
        if (vpnId) {
            item = await VPN.findById(vpnId);
            if (!item || !item.plans[planIndex]) return res.status(404).json({ success: false, message: "VPN Plan not found" });
            itemType = "VPN";
            title = "SMSGlobe VPN";
            amountInUSD = item.plans[planIndex].price;
            redirectUrl = "https://smsglobe.vercel.app/smsuser/user_vpn.html";
        } 
        // 2. Logic for Proxy
        else if (proxyId) {
            item = await Proxy.findById(proxyId);
            if (!item || !item.plans[planIndex]) return res.status(404).json({ success: false, message: "Proxy Plan not found" });
            itemType = "Proxy";
            title = "SMSGlobe Proxy";
            amountInUSD = item.plans[planIndex].price;
            redirectUrl = "https://smsglobe.vercel.app/smsuser/user_proxy.html";
        } 
        // 3. Logic for eSIM Refill
        else if (carrierName) {
            itemType = "eSIM";
            title = `eSIM Refill: ${carrierName}`;
            // Convert "$15.00" string from frontend to number 15
            amountInUSD = parseFloat(planAmount.replace(/[$,]/g, ''));
            redirectUrl = "https://smsglobe.vercel.app/smsuser/esim_refill.html";
        } else {
            return res.status(400).json({ success: false, message: "No product specified" });
        }

        const amountInNGN = Math.round(amountInUSD * USD_TO_NGN_RATE);
        const tx_ref = `SMS-${itemType}-${Date.now()}-${decoded.id.slice(-4)}`;

        const response = await fetch("https://api.flutterwave.com/v3/payments", {
            method: "POST",
            headers: {
                Authorization: `Bearer ${process.env.FLW_SECRET_KEY}`,
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                tx_ref: tx_ref,
                amount: amountInNGN,
                currency: "NGN",
                redirect_url: redirectUrl,
                customer: {
                    email: user.email,
                    name: user.fullName,
                },
                meta: {
                    userId: decoded.id,
                    productType: itemType,
                    // If eSIM, we store carrier and number. If VPN/Proxy, we store productId
                    productId: vpnId || proxyId || carrierName, 
                    planIndex: planIndex,
                    mobileNumber: mobileNumber || null, // Specific to eSIM
                    planAmount: planAmount || null      // Specific to eSIM
                },
                customizations: {
                    title: title,
                    description: itemType === "eSIM" 
                        ? `Refill for ${mobileNumber} (${planAmount})` 
                        : `${item.name} ($${amountInUSD} USD)`,
                    logo: "https://imgur.com/8YeZgfx.png"
                },
            }),
        });

        const data = await response.json();
        if (data.status === "success") {
            return res.json({ success: true, link: data.data.link });
        } else {
            return res.status(500).json({ success: false, message: "Flutterwave Error" });
        }
    } catch (err) {
        console.error("Initiate Payment Error:", err);
        return res.status(401).json({ success: false, message: "Unauthorized or Session Expired" });
    }
}

async function handleVerifyPayment(req, res) {
    const { transactionId } = req.body;

    try {
        const response = await fetch(`https://api.flutterwave.com/v3/transactions/${transactionId}/verify`, {
            method: "GET",
            headers: { Authorization: `Bearer ${process.env.FLW_SECRET_KEY}` },
        });

        const data = await response.json();

        if (data.status === "success" && data.data.status === "successful") {
            // 1. Extract Meta data (Including eSIM specific fields)
            const { productId, productType, planIndex, userId, mobileNumber, planAmount } = data.data.meta;
            
            // 2. Fetch the User
            const actualUser = await User.findById(userId);
            if (!actualUser) return res.status(404).json({ success: false, message: "User account not found" });

            const userEmail = actualUser.email; 
            const amountPaid = data.data.amount;
            const paymentRef = data.data.tx_ref;
            const currency = data.data.currency;

            let credentials = {};
            let productDetails = { name: "", plan: "" };
            let targetNum = null;

            // --- 3. HANDLE VPN PURCHASE ---
            if (productType === "VPN") {
                const item = await VPN.findOneAndUpdate(
                    { _id: productId, stock: { $gt: 0 } },
                    { $inc: { stock: -1 } },
                    { new: true, select: '+password' }
                );
                if (!item) return res.status(400).json({ success: false, message: "VPN out of stock" });

                productDetails.name = item.name;
                productDetails.plan = item.plans[planIndex]?.duration || "Standard Plan";
                credentials = {
                    type: "VPN",
                    username: item.username,
                    password: item.password,
                    instructions: item.instructions || "Check dashboard."
                };

            // --- 4. HANDLE PROXY PURCHASE ---
            } else if (productType === "Proxy") {
                const item = await Proxy.findOneAndUpdate(
                    { _id: productId, stock: { $gt: 0 } },
                    { $inc: { stock: -1 } },
                    { new: true }
                );
                if (!item) return res.status(400).json({ success: false, message: "Proxy out of stock" });

                productDetails.name = item.name;
                productDetails.plan = `${item.plans[planIndex]?.ip_count || 0} IPs`;
                credentials = {
                    type: "Proxy",
                    activationCode: item.activationCode,
                    instructions: item.instructions || "Check dashboard."
                };

            // --- 5. NEW: HANDLE ESIM REFILL ---
            } else if (productType === "eSIM") {
                productDetails.name = productId; // In eSIM initiate, we passed Carrier Name as productId
                productDetails.plan = planAmount; // e.g., "$15.00"
                targetNum = mobileNumber;         // The phone number to refill

                credentials = {
                    type: "eSIM",
                    instructions: "Your refill request has been received. Processing usually takes 5-30 minutes."
                };
            }

            // --- 6. CREATE ORDER (Saves everything to DB) ---
            try {
                await Order.create({
                    userId: userId,
                    userEmail: userEmail,
                    fullName: actualUser.fullName,
                    productType: productType,
                    planName: productDetails.plan,
                    nodeName: productDetails.name,
                    targetNumber: targetNum, // CRITICAL: This saves the eSIM mobile number
                    amount: amountPaid,      // The Naira amount paid
                    currency: currency, 
                    status: "successful",
                    paymentReference: paymentRef,
                    activationCode: credentials.activationCode,
                    vpnCredentials: productType === "VPN" ? {
                        username: credentials.username,
                        password: credentials.password
                    } : undefined
                });
            } catch (dbErr) {
                console.error("Order Record Failed:", dbErr);
            }

            // --- 7. DELIVERY EMAIL ---
            try {
                // You can modify your email template to handle eSIM instructions
                await sendDeliveryEmail(userEmail, credentials); 
            } catch (emailErr) {
                console.error("Email Delivery Failed:", emailErr);
            }
            const savedOrder = await Order.findOne({ paymentReference: paymentRef });
            
            return res.json({ 
                success: true, 
                credentials: credentials,
                order: savedOrder
            });
        }

        return res.status(400).json({ success: false, message: "Transaction verification failed." });

    } catch (err) {
        console.error("Payment Verification Error:", err);
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

    // 1. DYNAMIC CONTENT CONFIGURATION
    const isVPN = credentials.type === "VPN";
    const isESIM = credentials.type === "eSIM" || credentials.type === "eSIM Refill";
    const isProxy = credentials.type === "Proxy";
    
    let subject, headerTitle, subHeader;

    if (isVPN) {
        subject = "🔑 Your VPN Access Credentials";
        headerTitle = "Node Activated!";
        subHeader = "Your Premium VPN Access is ready.";
    } else if (isESIM) {
        // If there is a confirmation number, it's the final delivery. Otherwise, it's the "Request Received" notification.
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

    if (isVPN) {
        dataTableHtml = `
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
            </td>`;
    } else if (isESIM) {
        // ESIM REFILL LAYOUT (Handles both Initial Request and Admin Confirmation)
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
                    <span style="font-size: 9px; color: #667085; text-transform: uppercase; font-weight: bold;">Plan / Amount</span><br>
                    <strong style="font-size: 13px; color: #101828;">${credentials.amount}</strong>
                </td>
                <td class="mobile-full" width="50%" valign="top" style="text-align: right;">
                    <span style="font-size: 9px; color: #667085; text-transform: uppercase; font-weight: bold;">Confirmation #</span><br>
                    <strong style="font-size: 13px; font-family: 'Courier New', monospace; color: #F9861E;">${credentials.confirmationNumber || 'PENDING'}</strong>
                </td>
            </tr>`;
    } else {
        // PROXY TABLE LAYOUT (Activation Code & Amount)
        dataTableHtml = `
            <td class="mobile-full" width="50%" valign="top" style="padding-bottom: 10px;">
                <span style="font-size: 9px; color: #667085; text-transform: uppercase; font-weight: bold;">Activation Code</span><br>
                <strong style="font-size: 14px; font-family: 'Courier New', monospace; color: #0F54C6;">${credentials.activationCode || credentials.password}</strong>
            </td>
            <td class="mobile-full" width="50%" valign="top" style="text-align: right; padding-bottom: 10px;">
                <span style="font-size: 9px; color: #667085; text-transform: uppercase; font-weight: bold;">Amount Paid</span><br>
                <strong style="font-size: 14px; color: #101828;">${credentials.amount}</strong>
            </td>`;
    }

    const htmlContent = `
    <!DOCTYPE html>
    <html>
    <head>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            @media screen and (max-width: 480px) {
                .mobile-full { width: 100% !important; display: block !important; text-align: left !important; padding-bottom: 10px !important; }
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
                                <p style="font-size: 13px; margin: 0 0 20px 0; line-height: 1.6;">${credentials.instructions || 'Please follow the instructions on your dashboard to begin using your service.'}</p>
                                
                                <table border="0" cellpadding="0" cellspacing="0" width="100%" style="border-top: 1px solid #D1E0FF; padding-top: 15px;">
                                    <tr>
                                        ${dataTableHtml}
                                    </tr>
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

async function handleAdminEsimUpdate(req, res) {
    const { tid, status, confirmationNumber } = req.body;

    if (!tid || !status) {
        return res.status(400).json({ success: false, message: "Missing Transaction ID or Status" });
    }

    try {
        // FIX: Change 'EsimRefill' to 'Order' to match where the data is actually stored
        const updatedRefill = await Order.findOneAndUpdate(
            { paymentReference: tid, productType: 'eSIM' }, 
            { 
                $set: { 
                    status: status, 
                    confirmationNumber: confirmationNumber || null, 
                    updatedAt: new Date() 
                } 
            },
            { new: true } 
        );

        if (!updatedRefill) {
            return res.status(404).json({ success: false, message: "Transaction not found in Orders" });
        }

        const isFinished = status.toLowerCase() === 'completed' || status.toLowerCase() === 'successful';
        
        if (isFinished) {
            try {
                // Ensure all fields are mapped correctly from the Order model
                await sendDeliveryEmail(updatedRefill.userEmail, {
                    type: "eSIM",
                    amount: updatedRefill.planName, 
                    confirmationNumber: confirmationNumber || "Refill Processed",
                    carrierName: updatedRefill.nodeName || "eSIM Service",
                    mobileNumber: updatedRefill.targetNumber,
                    instructions: "Your eSIM refill has been applied successfully."
                });
            } catch (emailError) {
                console.error("Email Delivery Failed:", emailError);
            }
        }

        return res.json({ 
            success: true, 
            message: `Order updated to ${status}`,
            data: updatedRefill 
        });

    } catch (error) {
        console.error("Admin Update Error:", error);
        return res.status(500).json({ success: false, message: "Internal Server error" });
    }
}

// --- 8. STARTUP ---
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

if (process.env.NODE_ENV !== 'production') {
    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () => console.log(`Dev Server: http://localhost:${PORT}`));
}

module.exports = app;