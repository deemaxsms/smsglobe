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
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const multer = require('multer');

dotenv.config();
const app = express();

const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

cloudinary.config({
    cloud_name: process.env.CLOUDINARY_NAME,
    api_key: process.env.CLOUDINARY_KEY,
    api_secret: process.env.CLOUDINARY_SECRET
});

const storage = new CloudinaryStorage({
    cloudinary: cloudinary,
    params: {
        folder: 'smsglobe_receipts', // Name of the folder in Cloudinary
        allowed_formats: ['jpg', 'png', 'pdf'],
    },
});

const upload = multer({ storage: storage });

const smsBowerClient = axios.create({
    baseURL: 'https://smsbower.page/stubs/handler_api.php',
    params: {
        api_key: process.env.SMSBOWER_API_KEY
    }
});

app.use(cors());
app.use(express.json());

// --- 1. SERVE STATIC FILES ---

app.use('/assets', express.static(path.join(__dirname, 'assets')));

app.get('/style.css', (req, res) => {
    res.sendFile(path.join(__dirname, 'style.css'));
});

app.use(express.static(__dirname, { extensions: ['html'] }));

app.use('/smsadmin', express.static(path.join(__dirname, 'smsadmin'), {
    extensions: ['html', 'htm']
}));

app.use('/smsuser', express.static(path.join(__dirname, 'smsuser'), {
    extensions: ['html', 'htm']
}));

app.get('/sitemap.xml', (req, res) => {
    res.sendFile(path.join(__dirname, 'sitemap.xml'));
});

app.get('/robots.txt', (req, res) => {
    res.sendFile(path.join(__dirname, 'robots.txt'));
});

const JWT_SECRET = process.env.JWT_SECRET;
const RECAPTCHA_SECRET = process.env.RECAPTCHA_SECRET_KEY;
const SMSBOWER_BASE_URL = 'https://smsbower.page/stubs/handler_api.php';
const SMSBOWER_API_KEY = process.env.SMSBOWER_API_KEY;

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
    isVerified: { type: Boolean, default: false },
    otpCode: { type: String },
    otpExpires: { type: Date },
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
    smsMarkupPercentage: { type: Number, default: 0 }, // <--- ADD THIS FIELD FOR SMS ONLY
    noticeBarText: { type: String, default: "Welcome to SMSGlobe!" },
    supportWhatsapp: { type: String, default: "" }
}, { timestamps: true });

const SystemSettings = mongoose.models.SystemSettings || mongoose.model('SystemSettings', systemSettingsSchema, 'system_settings');

const vpnSchema = new mongoose.Schema({
    name: { type: String, required: true },
    provider: { type: String, required: true },
    region: { type: String, required: true },
    image: String,   
    deviceType: { type: String, enum: ['Phone', 'PC', 'Both'], default: 'Phone' },
    stock: { type: Number, default: 0 },
    deviceLimit: { type: Number, default: 1 },
    plans: [{
        duration: { type: String, required: true },
        price: { type: Number, required: true }
    }],        
    
    phoneAccounts: [{
        username: { type: String },
        password: { type: String }
    }],

    pcMethod: { type: String, enum: ['userpass', 'code'] }, 
    pcAccounts: [{
        username: { type: String }, // Used if method is 'userpass'
        password: { type: String }, // Used if method is 'userpass'
        activationCode: { type: String } // Used if method is 'code'
    }],

    instructions: { type: String }
}, { timestamps: true });

vpnSchema.pre('save', async function() {
    const phoneCount = this.phoneAccounts ? this.phoneAccounts.length : 0;
    const pcCount = this.pcAccounts ? this.pcAccounts.length : 0;    
    this.stock = phoneCount + pcCount;
    
});

const VPN = mongoose.models.VPN || mongoose.model('VPN', vpnSchema);

const ProxySchema = new mongoose.Schema({
    name: { type: String, required: true },
    category: { type: String, default: 'Standard' },
    stock: { type: Number, default: 0 },
    plans: [{
        ip_count: { type: Number, required: true },
        price: { type: Number, required: true } 
    }],
    activationCode: String, // Single code (for UI preview)
    activationCodes: [String], // <--- ADD THIS: Full inventory array
    imageUrl: String, // Ensure this exists if you use it
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
    ram: String, 
    cpu: String, 
    storage: String, 
    net: String, 
    os: String,
    amount: Number,
    receiptUrl: String,
    extraCPU: { type: Number, default: 0 },
    extraStorage: { type: Number, default: 0 },
    currency: { type: String, default: "NGN" },
    status: { type: String, default: "successful" },
    paymentReference: String,
    ipAddress: { type: String, default: "N/A" },
    port: { type: String, default: "3389" },
    rdpUsername: { type: String, default: "Admin" },
    rdpPassword: { type: String },
    confirmationNumber: { type: String },
    metadata: { 
        extraCPU: Number, 
        extraStorage: Number, 
        osChoice: String,
        ram: String,
        cpu: String,
        storage: String
    }
}, { timestamps: true });

const RDP = mongoose.models.RDP || mongoose.model('RDP', rdpSchema, 'rdp_orders');

const esimRefillSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    userEmail: { type: String, required: true, index: true },
    fullName: { type: String },    
    carrier: {
        id: { type: String, required: true }, 
        name: { type: String, required: true }, 
        image: { type: String } 
    },
    target: {
        number: { type: String, required: true }, // The phone number being topped up
        country: { type: String, required: true } // The coverage country
    },
    amount: { type: Number, required: true }, // Total cost in NGN
    currency: { type: String, default: 'NGN' },
    mainBalanceUsed: { type: Number, default: 0 },
    bonusBalanceUsed: { type: Number, default: 0 },
    paymentReference: { type: String, unique: true, required: true }, // WAL- or ESIM- prefix    
    status: { 
        type: String, 
        enum: ['pending', 'processing', 'successful', 'failed', 'completed'], 
        default: 'pending',
        index: true 
    },
    confirmationNumber: { type: String }, 
    receiptUrl: String,
    adminNote: { type: String },
    metadata: { type: mongoose.Schema.Types.Mixed }
}, { timestamps: true });

esimRefillSchema.index({ createdAt: -1 });
const EsimRefill = mongoose.models.EsimRefill || mongoose.model('EsimRefill', esimRefillSchema, 'esim_refills');

// --- eSIM ACTIVATION SCHEMA ---
const esimActivationSchema = new mongoose.Schema({
    // User Identity
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    userEmail: { type: String, required: true, index: true },
    
    customerDetails: {
        firstName: { type: String, required: true },
        lastName: { type: String, required: true },
        address: { type: String },
        zipCode: { type: String },
        email: { type: String } // The specific activation email provided in the form
    },
    carrier: {
        name: { type: String, required: true }, // e.g., T-Mobile, AT&T
        image: { type: String } 
    },
    receiptUrl: String,
    activationType: { type: String, required: true }, // e.g., 'Prepaid', 'Data-Only'
    deviceName: { type: String, required: true },    // The device name/model provided in 'targetNumber' field
    amount: { type: Number, required: true }, 
    mainBalanceUsed: { type: Number, default: 0 },
    bonusBalanceUsed: { type: Number, default: 0 },
    paymentReference: { type: String, unique: true, required: true }, // e.g., ACT-XXXXX
    status: { 
        type: String, 
        enum: ['pending', 'processing', 'successful', 'failed', 'completed'], 
        default: 'pending',
        index: true 
    },
    adminNote: { type: String },    
    metadata: { type: mongoose.Schema.Types.Mixed }
}, { timestamps: true });

esimActivationSchema.index({ createdAt: -1 });
const EsimActivation = mongoose.models.EsimActivation || mongoose.model('EsimActivation', esimActivationSchema, 'esim_activations');


const smsNumberSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    userEmail: { type: String, required: true },
    
    // Vendor Identity (Xentrahub)
    vendorOrderId: { type: String, index: true }, // Order ID returned by Xentrahub
    countryId: { type: String }, // Country code/ID selected
    phoneNumber: { type: String }, // The virtual number assigned
    serviceName: { type: String, required: true }, // e.g., 'WhatsApp', 'Telegram'
    
    // Order Details
    amount: { type: Number, required: true }, // Final markup-adjusted price charged
    status: { 
        type: String, 
        enum: ['pending', 'completed', 'expired', 'failed'], 
        default: 'pending',
        index: true 
    },
    
    smsCode: { type: String }, // The extracted 4-6 digit code
    fullMessage: { type: String }, // The raw SMS text for backup
    
    expiresAt: { 
        type: Date, 
        default: () => new Date(+new Date() + 15 * 60 * 1000) // Auto-expire after 15 mins
    }
}, { timestamps: true });

smsNumberSchema.index({ vendorOrderId: 1, status: 1, createdAt: -1 });

const SmsNumber = mongoose.models.SmsNumber || mongoose.model('SmsNumber', smsNumberSchema);

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
        enum: ['VPN', 'Proxy', 'eSIM', 'eSIM_Refill', 'eSIM_Activation', 'RDP', 'RentedNumber', 'SmsNumber'], 
        required: true 
    },
    planName: String, 
    nodeName: String, 
    amount: { type: Number, required: true },
    currency: { type: String, default: 'NGN' },         
    mainBalanceUsed: { type: Number, default: 0 }, 
    bonusBalanceUsed: { type: Number, default: 0 }, 
    status: { 
        type: String, 
        enum: ['pending', 'processing', 'successful', 'failed', 'completed'], 
        default: 'pending' 
    }, 
    paymentReference: { type: String, unique: true },    
    targetNumber: String, 
    country: String,
    target: {
        number: String,
        country: String
    },
    carrier: {
        id: String,
        name: String,
        image: String
    },
    confirmationNumber: { type: String },
    instructions: String, 
    adminNote: String, 
    receiptUrl: String,
    ram: String,
    cpu: String,   // This allows "2 Cores" to be stored at the top level
    storage: String,
    net: String,   // This allows "1Gbps" to be stored at the top level
    os: String,
    ipAddress: String,    // Critical: Allows saving the IP
    port: { type: String, default: '3389' }, // Critical: Allows saving the Port
    rdpUsername: String,  // Critical: Allows saving the Username
    rdpPassword: String,  // Critical: Allows saving the Password
    deliveredAt: Date,
    extraCPU: { type: Number, default: 0 },
    extraStorage: { type: Number, default: 0 },    
    activationCode: String, 
    vpnCredentials: { username: String, password: { type: String } },
    pcUsername: String,
    pcPassword: String,
    pcMethod: String, 
    metadata: { type: mongoose.Schema.Types.Mixed } 
    
}, { timestamps: true });

// Optimize for dashboard performance
orderSchema.index({ createdAt: -1 });

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
    const count = await User.countDocuments({ referredBy: user.referralCode });
    return count;
}
async function generateUniqueCode() {
    let isUnique = false;
    let code = "";
    while (!isUnique) {
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

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

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
        case 'verify-otp': return handleVerifyOTP(req, res);
        case 'user-login': return handleUserLogin(req, res);
        case 'user-profile': return handleGetUserProfile(req, res);
        case 'user-messages': return handleGetUserMessages(req, res);
        case 'user-orders': return handleGetUserOrders(req, res);
        case 'sms-receive': return handleSmsWebhook(req, res);
        case 'order-details':  return handleGetOrderDetails(req, res);
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
    case 'update-esim-status': return await handleAdminEsimUpdate(req, res);

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
    case 'services':
        if (req.method === 'GET') return handleGetServicesAndPrices(req, res);
        break;
    case 'countries':
        if (req.method === 'GET') return handleGetCountries(req, res);
        break;
    case 'get-numbers': return handleGetNumbers(req, res);
    case 'get-countries': return handleGetCountries(req, res);
     case 'get-stock':  return handleGetStock(req, res);
     case 'sms-receive':  return handleSmsReceive(req, res);
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
    const isHuman = await verifyRecaptcha(captchaToken);    
    if (!isHuman) {
        console.log(`Admin login blocked: reCAPTCHA failed for ${email}`); 
        return res.status(400).json({ 
            success: false, 
            message: "reCAPTCHA verification failed. Please refresh and try again." 
        });
    }
    try {
        const admin = await Admin.findOne({ email });
        
        if (!admin || !(await bcrypt.compare(password, admin.password))) {
            return res.status(401).json({ success: false, message: "Invalid admin credentials" });
        }
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
            targetAccount = new Model({
                fullName: name,
                email: email.toLowerCase(),
                password: await bcrypt.hash(Math.random().toString(36), 12)
            });
            await targetAccount.save();
        }
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
          { returnDocument: 'after' }
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
            .select('+phoneAccounts +pcAccounts +pcMethod +deviceType +stock +deviceLimit +instructions'); 
            
        res.json({ success: true, products: vpns }); 
    } catch (err) {
        console.error("Fetch VPN Error:", err);
        res.status(500).json({ success: false, message: "Failed to fetch VPN list" });
    }
}
async function handleAddVPN(req, res) {
    try {
        const { plans, deviceType, deviceLimit, phoneAccounts, pcAccounts, ...otherData } = req.body;

        // 1. Format Plans
        let formattedPlans = [];
        if (plans && Array.isArray(plans)) {
            formattedPlans = plans.map(p => ({
                duration: p.duration || "1 Month",
                price: Math.round(parseFloat(p.price)) || 0
            }));
        }

        const newVPN = new VPN({
            ...otherData,
            plans: formattedPlans,
            phoneAccounts: phoneAccounts || [],
            pcAccounts: pcAccounts || [],
            deviceType: normalizeDeviceType(deviceType),
            deviceLimit: parseInt(deviceLimit) || 1,
            // Price is taken from the first plan tier for display
            price: formattedPlans.length > 0 ? formattedPlans[0].price : 0
        });

        // This triggers the pre('save') middleware in your schema to auto-calculate stock
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
        const { vpnId, id, plans, phoneAccounts, pcAccounts, deviceType, ...updateData } = req.body;
        const targetId = vpnId || id;

        if (!targetId) {
            return res.status(400).json({ success: false, message: "VPN ID is required" });
        }

        // 1. Explicitly Map Bulk Accounts & Normalize Type
        if (phoneAccounts) updateData.phoneAccounts = phoneAccounts;
        if (pcAccounts) updateData.pcAccounts = pcAccounts;
        if (deviceType) updateData.deviceType = normalizeDeviceType(deviceType);

        // 2. Format Plans
        if (plans && Array.isArray(plans)) {
            updateData.plans = plans.map(p => ({
                duration: p.duration || "1 Month",
                price: Math.round(parseFloat(p.price)) || 0
            }));
            
            if (updateData.plans.length > 0) {
                updateData.price = updateData.plans[0].price;
            }
        }

        // 3. Sync Stock Count (Manual sync since findByIdAndUpdate skips pre-save middleware)
        if (phoneAccounts || pcAccounts) {
            const pCount = phoneAccounts ? phoneAccounts.length : 0;
            const cCount = pcAccounts ? pcAccounts.length : 0;
            updateData.stock = pCount + cCount;
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

        // Check if the user has verified their email via OTP
        if (user.isVerified === false) {
            return res.status(403).json({ 
                success: false, 
                isUnverified: true, // Frontend flag to trigger OTP modal
                message: "Please verify your email address to continue." 
            });
        }

        if (user.status === 'suspended') {
            return res.status(403).json({ 
                success: false, 
                message: "Your account has been suspended. Contact support." 
            });
        }

        if (!JWT_SECRET) throw new Error("JWT_SECRET is not defined.");

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
                hasDeposited: user.hasDeposited || false,
                referralCount: user.referralCount || 0,
                referralCode: user.referralCode
            } 
        });

    } catch (err) {
        console.error("========== LOGIN ERROR ==========");
        console.error(err.message);
        return res.status(500).json({ success: false, message: "Internal server error." });
    }
}

async function handleUserRegister(req, res) {
    const { fullName, email, password, captchaToken, friendReferralCode } = req.body;

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

        if (existingUser && existingUser.isVerified) {
            return res.status(400).json({ success: false, message: "This email is already registered." });
        }

        if (friendReferralCode && friendReferralCode.trim().length > 0) {
            const cleanFriendCode = friendReferralCode.trim().toUpperCase();
            const referrer = await User.findOne({ referralCode: cleanFriendCode });
            if (!referrer) {
                return res.status(400).json({ success: false, message: "The referral code provided is invalid." });
            }
        }

        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const otpExpires = Date.now() + 10 * 60 * 1000; 

        const myNewReferralCode = await generateUniqueCode();
        const hashedPassword = await bcrypt.hash(password, 12);

        const userData = {
            fullName: fullName.trim(),
            email: normalizedEmail,
            password: hashedPassword,
            balance: 0,
            bonusBalance: 0,
            hasDeposited: false,
            referralCode: myNewReferralCode,
            referredBy: friendReferralCode ? friendReferralCode.trim().toUpperCase() : null,
            referralCount: 0,
            isVerified: false,
            otpCode: otp,
            otpExpires: otpExpires
        };

        if (existingUser) {
            await User.updateOne({ email: normalizedEmail }, userData);
        } else {
            const newUser = new User(userData);
            await newUser.save();
        }

       await transporter.sendMail({
    from: '"SMSGlobe" <noreply@smsglobe.com>',
    to: normalizedEmail,
    subject: "Verify your SMSGlobe Account",
    html: `
        <!DOCTYPE html>
        <html>
        <head>
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                @media only screen and (max-width: 480px) {
                    .container { padding: 20px !important; }
                    .otp-text { font-size: 24px !important; letter-spacing: 4px !important; }
                    .brand-logo { height: 24px !important; }
                }
            </style>
        </head>
        <body style="margin: 0; padding: 0; background-color: #F0F5FE; font-family: 'Inter', Helvetica, Arial, sans-serif;">
            <table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%">
                <tr>
                    <td align="center" style="padding: 40px 10px;">
                        <table class="container" role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%" style="max-width: 440px; background-color: #ffffff; border: 1px solid #EAECF0; border-radius: 24px; padding: 32px; box-shadow: 0 4px 12px rgba(15, 84, 198, 0.05);">
                            <tr>
                                <td align="center" style="padding-bottom: 24px;">
                                    <img src="https://imgur.com/8YeZgfx.png" alt="SMSGlobe" class="brand-logo" style="height: 28px; width: auto; display: block; outline: none; border: none; text-decoration: none;">
                                </td>
                            </tr>
                            
                            <tr>
                                <td align="center">
                                    <h2 style="margin: 0; color: #101828; font-size: 20px; font-weight: 700; line-height: 1.2;">Verify your email</h2>
                                    <p style="margin: 12px 0 0 0; color: #667085; font-size: 14px; line-height: 1.5;">
                                        Thanks for joining SMSGlobe! Please use the verification code below to complete your registration.
                                    </p>
                                </td>
                            </tr>

                            <tr>
                                <td align="center" style="padding: 32px 0;">
                                    <div class="otp-text" style="background-color: #F9FAFB; border: 1px dashed #D0D5DD; border-radius: 12px; padding: 16px; font-size: 32px; font-weight: 800; letter-spacing: 8px; color: #0F54C6; display: inline-block;">
                                        ${otp}
                                    </div>
                                    <p style="margin: 12px 0 0 0; color: #F9861E; font-size: 12px; font-weight: 600;">Code expires in 10 minutes</p>
                                </td>
                            </tr>

                            <tr>
                                <td align="center" style="border-top: 1px solid #EAECF0; padding-top: 24px;">
                                    <p style="margin: 0; color: #98A2B3; font-size: 11px; line-height: 1.4;">
                                        If you didn't request this code, you can safely ignore this email.
                                    </p>
                                    <p style="margin: 8px 0 0 0; color: #98A2B3; font-size: 11px;">
                                        &copy; 2026 SMSGlobe. All rights reserved.
                                    </p>
                                </td>
                            </tr>
                        </table>
                    </td>
                </tr>
            </table>
        </body>
        </html>
    `
});

        return res.status(200).json({ 
            success: true, 
            message: "Verification code sent to your email!" 
        });

    } catch (err) {
        console.error("Registration Error:", err);
        return res.status(500).json({ success: false, message: "Failed to process registration." });
    }
}

async function handleVerifyOTP(req, res) {
    const { email, otp } = req.body;

    try {
        const user = await User.findOne({ 
            email: email.toLowerCase().trim(),
            otpCode: otp,
            otpExpires: { $gt: Date.now() }
        });

        if (!user) {
            return res.status(400).json({ success: false, message: "Invalid or expired verification code." });
        }

        // CRITICAL: Only process referral rewards if the user is not already verified
        if (!user.isVerified) {
            user.isVerified = true;
            user.otpCode = undefined;
            user.otpExpires = undefined;

            if (user.referredBy) {
                const cleanReferralCode = user.referredBy.trim().toUpperCase();
                const referrer = await User.findOne({ referralCode: cleanReferralCode });
                
                if (referrer) {
                    referrer.referralCount = (referrer.referralCount || 0) + 1;
                    
                    // The 10th, 20th, 30th... referral gets ₦3,000
                    if (referrer.referralCount % 10 === 0) {
                        referrer.bonusBalance = (referrer.bonusBalance || 0) + 3000;
                    }
                    await referrer.save();
                }
            }
            
            // Save the verified status and cleaned OTP fields
            await user.save();
        }

        return res.status(200).json({ 
            success: true, 
            message: "Email verified successfully! You can now log in." 
        });

    } catch (err) {
        console.error("OTP Verification Error:", err);
        return res.status(500).json({ success: false, message: "Verification failed." });
    }
}

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

        // --- ADDED VERIFICATION CHECK ---
        if (user.isVerified === false) {
            return res.status(403).json({ 
                success: false, 
                isUnverified: true,
                message: "Email verification required",
                status: 'unverified'
            });
        }

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
            isVerified: user.isVerified, // Included for frontend UI state
            balance: user.balance || 0, 
            bonusBalance: user.bonusBalance || 0, 
            hasDeposited: user.hasDeposited || "",
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
    // 1. DESTRUCTURING (All body variables defined here)
    const { 
        vpnId, proxyId, rdpId, 
        carrierName, carrierId, productImage, 
        coverageCountry, mobileNumber,        
        planAmount, planIndex, 
        metadata, planName, useBonus 
    } = req.body;
    
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    try {
        if (!token) return res.status(401).json({ success: false, message: "Unauthorized" });
        
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        
        // FETCH FRESH USER DATA
        const user = await User.findById(decoded.id);
        if (!user) return res.status(404).json({ success: false, message: "User not found" });

        // IDEMPOTENCY CHECK
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
        let isOnlineSimFlow = false; // Flag to execute downstream vendor calls safely

        if (vpnId) {
            const vpnLookup = await VPN.findById(vpnId).select('+phoneAccounts +pcAccounts');
            if (!vpnLookup || (vpnLookup.stock || 0) <= 0) {
                return res.status(404).json({ success: false, message: "VPN unavailable or out of stock" });
            }
            if (!vpnLookup.plans || !vpnLookup.plans[planIndex]) {
                return res.status(400).json({ success: false, message: "Invalid plan selected" });
            }

            itemType = "VPN";
            costNGN = Math.round(Number(vpnLookup.plans[planIndex].price));
            productDetails.name = vpnLookup.name;
            productDetails.plan = vpnLookup.plans[planIndex].duration;

            let assigned = null;
            let popQuery = {};

            if (vpnLookup.pcAccounts && vpnLookup.pcAccounts.length > 0) {
                assigned = vpnLookup.pcAccounts[0];
                popQuery = { $pop: { pcAccounts: -1 }, $inc: { stock: -1 } };
            } else if (vpnLookup.phoneAccounts && vpnLookup.phoneAccounts.length > 0) {
                assigned = vpnLookup.phoneAccounts[0];
                popQuery = { $pop: { phoneAccounts: -1 }, $inc: { stock: -1 } };
            }

            if (!assigned) {
                return res.status(404).json({ success: false, message: "No credentials available in the database" });
            }

            const item = await VPN.findOneAndUpdate(
                { _id: vpnId, stock: { $gt: 0 } },
                popQuery,
                { returnDocument: 'after', select: '+instructions +deviceLimit' }
            );

            orderSpecifics = {
                vpnCredentials: { username: assigned.username || "", password: assigned.password || "" },
                username: assigned.username || "", 
                password: assigned.password || "",
                pcUsername: assigned.username || "",
                pcPassword: assigned.password || "",
                activationCode: assigned.activationCode || "",
                instructions: item.instructions || "Check your dashboard for setup steps.",
                deviceLimit: item.deviceLimit || 1
            };
        }

        else if (proxyId) {
            const proxyLookup = await Proxy.findById(proxyId).select('+activationCodes');
            if (!proxyLookup || (proxyLookup.stock || 0) <= 0) {
                return res.status(404).json({ success: false, message: "Proxy unavailable or out of stock" });
            }
            if (!proxyLookup.plans || !proxyLookup.plans[planIndex]) {
                return res.status(400).json({ success: false, message: "Invalid plan selected" });
            }
            const availableCodes = proxyLookup.activationCodes || [];
            if (availableCodes.length === 0) {
                return res.status(404).json({ success: false, message: "No activation codes available" });
            }
            const assignedCode = availableCodes[0];

            const item = await Proxy.findOneAndUpdate(
                { _id: proxyId, stock: { $gt: 0 } },
                { $pop: { activationCodes: -1 }, $inc: { stock: -1 } },
                { returnDocument: 'after', select: '+instructions' }
            );

            itemType = "Proxy";
            costNGN = Math.round(Number(item.plans[planIndex].price));
            productDetails.name = item.name;
            productDetails.plan = `${item.plans[planIndex].ip_count || 0} IPs`;

            orderSpecifics = {
                activationCode: assignedCode, 
                instructions: item.instructions || "To activate your proxy, copy the code above into your provider's portal.",
                metadata: { ...metadata, deliveredCode: assignedCode }
            };
        }


else if (metadata?.serviceType === 'virtual_number') {
            itemType = "SmsNumber"; 
            
            // 1. Fetch system settings for SMS markup percentage
            const settings = await SystemSettings.findOne();
            const smsMarkup = settings?.smsMarkupPercentage || 0; 

            const baseAmount = Number(planAmount);
            if (!baseAmount || isNaN(baseAmount)) {
                return res.status(400).json({ 
                    success: false, 
                    message: "Invalid plan amount received for virtual number purchase." 
                });
            }

            costNGN = Math.round(baseAmount * (1 + smsMarkup / 100));

            productDetails.name = `OnlineSIM Global Provision (${metadata.countryCode || 'NG'})`;
            productDetails.plan = metadata.serviceName || "SMS Verification";
            isOnlineSimFlow = true;

            // 2. Check Xentrahub balance before pulling from user wallet
            try {
                const xentraBalanceRes = await axios.get(`${XENTRA_API_BASE}/balance`, {
                    headers: { 'Authorization': `Bearer ${XENTRA_API_KEY}` }
                });

                const xentraBalance = xentraBalanceRes.data?.balance || 0;

                // Ensure Xentrahub has enough provider funds based on the dynamic base amount required
                if (xentraBalance < baseAmount) {
                    return res.status(400).json({ 
                        success: false, 
                        message: "System provider balance is currently low. Please contact support or try again shortly." 
                    });
                }
            } catch (err) {
                console.error("Xentrahub Balance Verification Error:", err.response?.data || err.message);
                return res.status(500).json({ 
                    success: false, 
                    message: "Failed to communicate with SMS provider gateway." 
                });
            }

            orderSpecifics = {
                serviceName: metadata.serviceName,
                status: 'pending', 
                instructions: "Allocating lease from dynamic server fields... Please stand by.",
                metadata: { 
                    ...metadata, 
                    provider: 'onlinesim',
                    markupApplied: smsMarkup
                }
            };
        }

        else if (rdpId) {
            itemType = "RDP";
            const rdpPlans = {
                tier1: { id: "tier1", name: "USA Tier 1", price: 30000, ram: "4GB", cpu: "2 Cores", storage: "60GB SSD", net: "1Gbps" },
                tier2: { id: "tier2", name: "USA Tier 2", price: 40000, ram: "6GB", cpu: "3 Cores", storage: "100GB SSD", net: "1Gbps" },
                tier3: { id: "tier3", name: "USA Tier 3", price: 50000, ram: "8GB", cpu: "4 Cores", storage: "140GB SSD", net: "2Gbps" },
                tier4: { id: "tier4", name: "USA Tier 4", price: 65000, ram: "12GB", cpu: "6 Cores", storage: "180GB SSD", net: "2Gbps" },
                tier5: { id: "tier5", name: "USA Tier 5", price: 80000, ram: "18GB", cpu: "8 Cores", storage: "240GB SSD", net: "3Gbps" },
                tier6: { id: "tier6", name: "USA Tier 6", price: 95000, ram: "24GB", cpu: "8 Cores", storage: "280GB SSD", net: "3Gbps" }
            };
            const selectedTier = rdpPlans[rdpId];
            if (!selectedTier) return res.status(404).json({ success: false, message: "RDP Plan not found" });
            const extraCPUCount = parseInt(metadata?.extraCPU || 0);
            const extraStorageGB = parseInt(metadata?.extraStorage || 0);
            costNGN = Math.round(Number(selectedTier.price) + (extraCPUCount * 5000) + (extraStorageGB * 5000));
            productDetails.name = selectedTier.name;
            productDetails.plan = `${selectedTier.ram} RAM | ${metadata?.osChoice || 'Windows Server'}`;
            
            orderSpecifics = {
                ram: selectedTier.ram,
                cpu: selectedTier.cpu,
                storage: selectedTier.storage,
                net: selectedTier.net,
                os: metadata?.osChoice || "Windows Server",
                extraCPU: extraCPUCount,
                extraStorage: extraStorageGB,
                ipAddress: "",
                rdpUsername: "",
                rdpPassword: "",
                port: ""
            };
        }
        else if (metadata?.activationEmail && metadata?.firstName) {
            itemType = "eSIM_Activation";
            const cleanedPrice = planAmount.toString().split('.')[0].replace(/[^0-9]/g, "");
            costNGN = Math.round(Number(cleanedPrice));

            productDetails.name = carrierName || "Global eSIM";
            productDetails.plan = planName || `₦${costNGN.toLocaleString()} Activation`;

            orderSpecifics = {
                carrier: { name: carrierName, image: productImage },
                deviceName: mobileNumber, 
                customerDetails: {
                    firstName: metadata.firstName,
                    lastName: metadata.lastName,
                    address: metadata.address,
                    zipCode: metadata.zip,
                    email: metadata.activationEmail
                },
                instructions: "Payment Confirmed. SMSGlobe is verifying your activation details."
            };
        }
        else if (carrierName && mobileNumber) {
            itemType = "eSIM_Refill";    
            const cleanedPrice = planAmount.toString().replace(/[^0-9]/g, "");
            costNGN = Math.round(Number(cleanedPrice));    
            productDetails.name = carrierName;
            productDetails.plan = `₦${costNGN.toLocaleString()}`; 
            orderSpecifics = {
                productType: "eSIM_Refill",
                nodeName: carrierName,
                planName: `₦${costNGN.toLocaleString()}`,        
                carrier: { id: carrierId || 'manual', name: carrierName, image: productImage },        
                target: { number: mobileNumber, country: coverageCountry || 'Global' },        
                targetNumber: mobileNumber,
                country: coverageCountry || 'Global',         
                instructions: "Payment Confirmed. Your refill is being processed by the technical team.",
                status: 'pending'
            };
        }

        // --- WALLET CALCULATIONS ---
        const mainBal = Number(user.balance || 0);
        const bonusBal = Number(user.bonusBalance || 0);
        const isBonusUnlocked = user.hasDeposited || mainBal > 0;
        const canUseBonus = useBonus === true && isBonusUnlocked && bonusBal > 0;        
        const buyingPower = canUseBonus ? (mainBal + bonusBal) : mainBal;

        if (buyingPower < costNGN) {
            if (vpnId) await VPN.findByIdAndUpdate(vpnId, { $inc: { stock: 1 } });
            if (proxyId) await Proxy.findByIdAndUpdate(proxyId, { $inc: { stock: 1 } });

            let errorMsg = `Insufficient Funds. Required: ₦${costNGN.toLocaleString()}.`;
            if (!useBonus && (mainBal + bonusBal) >= costNGN) {
                errorMsg += " (Try enabling your Bonus Balance)";
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
        mainDeduction = remainingToPay;

        // ATOMIC USER DEBIT CONTEXT
        const updatedUser = await User.findOneAndUpdate(
            { _id: user._id, balance: { $gte: mainDeduction } },
            { $inc: { balance: -mainDeduction, bonusBalance: -bonusDeduction } },
            { returnDocument: 'after' }
        );

        if (!updatedUser) {
            if (vpnId) await VPN.findByIdAndUpdate(vpnId, { $inc: { stock: 1 } });
            if (proxyId) await Proxy.findByIdAndUpdate(proxyId, { $inc: { stock: 1 } });
            return res.status(400).json({ success: false, message: "Transaction failed." });
        }

        // --- EXCLUSIVE LIVE ONLINESIM API ALLOCATION ---
        if (isOnlineSimFlow) {
            try {
                const api_key = process.env.ONLINESIM_API_KEY;
                const reqCountry = (metadata.countryCode || 'NG').toLowerCase();
                const reqService = (metadata.serviceName || 'whatsapp').toLowerCase();

                const osUrl = `https://onlinesim.io/api/getNum.php?apikey=${api_key}&service=${reqService}&country=${reqCountry}`;
                const osResponse = await axios.get(osUrl, { timeout: 15000 });

                // OnlineSIM gives response: "1" for a valid purchase transaction
                if (osResponse.data?.response === '1' || osResponse.data?.tzid) {
                    const allocatedNumber = osResponse.data.number;
                    const trackingTzid = osResponse.data.tzid;

                    // Re-assign localized variables with live data points
                    orderSpecifics.deviceId = trackingTzid; // Used as the identifier for polling checks
                    orderSpecifics.vendorOrderId = trackingTzid;
                    orderSpecifics.targetNumber = allocatedNumber;
                    orderSpecifics.instructions = "OnlineSIM allocated line successfully. Waiting for incoming code stream...";
                    
                    if (!orderSpecifics.metadata) orderSpecifics.metadata = {};
                    orderSpecifics.metadata.allocatedNumber = allocatedNumber;
                    orderSpecifics.metadata.tzid = trackingTzid;

                    // Generate auxiliary entry record for monitoring tools
                    await SmsNumber.create({
                        userId: user._id,
                        userEmail: user.email,
                        deviceId: trackingTzid,
                        vendorOrderId: trackingTzid,
                        phoneNumber: allocatedNumber,
                        serviceName: metadata.serviceName,
                        amount: costNGN,
                        status: 'pending'
                    });
                } else {
                    // Reverse user charges cleanly if external API allocation fails
                    await User.findByIdAndUpdate(user._id, { 
                        $inc: { balance: mainDeduction, bonusBalance: bonusDeduction } 
                    });
                    return res.status(400).json({ 
                        success: false, 
                        message: `Line Reservation Failed: ${osResponse.data?.error || "Vendor out of stock"}` 
                    });
                }
            } catch (apiErr) {
                console.error("Critical OnlineSIM API connection block:", apiErr.message);
                await User.findByIdAndUpdate(user._id, { 
                    $inc: { balance: mainDeduction, bonusBalance: bonusDeduction } 
                });
                return res.status(502).json({ success: false, message: "External vendor API processing timeout." });
            }
        }

        const paymentReference = `WAL-${Date.now()}-${user._id.toString().slice(-4)}`;

        // CREATE SYSTEM ORDER ENTRY
        const newOrder = await Order.create({
            userId: user._id,
            userEmail: user.email,
            fullName: user.fullName || "Customer",
            productType: itemType,
            planName: productDetails.plan,
            nodeName: productDetails.name,
            amount: costNGN,
            mainBalanceUsed: mainDeduction,
            bonusBalanceUsed: bonusDeduction,
            currency: "NGN",            
            status: isOnlineSimFlow ? "pending" : "successful", // Explicitly keep Virtual Numbers pending code capture
            paymentReference: paymentReference,
            targetNumber: orderSpecifics.targetNumber || mobileNumber || orderSpecifics.target?.number,
            country: coverageCountry || orderSpecifics.target?.country || metadata.countryCode || "NG",
            target: {
                number: orderSpecifics.targetNumber || mobileNumber || orderSpecifics.target?.number,
                country: coverageCountry || orderSpecifics.target?.country || metadata.countryCode || "NG"
            },
            carrier: orderSpecifics.carrier || { name: carrierName, image: productImage },
            ...orderSpecifics,
            metadata: { 
                ...metadata,
                ...orderSpecifics.metadata,
                isManualProcess: (itemType === "eSIM_Refill" || itemType === "eSIM_Activation")
            }
        });

        // TRANSACTION LOG
        await Transaction.create({
            userId: user._id,
            type: 'debit',
            purpose: 'purchase',
            amountNGN: costNGN,
            status: 'successful',
            reference: paymentReference,
            paymentMethod: 'wallet_combined',            
            balanceBefore: mainBal,
            balanceAfter: updatedUser.balance,
            bonusBefore: bonusBal,
            bonusAfter: updatedUser.bonusBalance,
            metadata: { orderId: newOrder._id, product: productDetails.name }
        });
        
        const manualProducts = ["eSIM_Refill", "eSIM_Activation", "RDP"];
        const isManual = manualProducts.includes(itemType);

        // Disabling immediate emails for virtual lines since they are received live on screen
        if (!isManual && !isOnlineSimFlow) {
            const deliveryCode = orderSpecifics.activationCode || newOrder.activationCode || "N/A";
            const deliveryInstructions = orderSpecifics.instructions || newOrder.instructions || "Check dashboard for details.";

            await sendDeliveryEmail(user.email, { 
                ...orderSpecifics, 
                productType: itemType, 
                nodeName: productDetails.name, 
                planName: productDetails.plan || newOrder.planName,
                amount: costNGN, 
                paymentReference: paymentReference,
                credentials: {
                    ...orderSpecifics,
                    activationCode: deliveryCode,
                    instructions: deliveryInstructions,
                    nodeName: productDetails.name,
                    planName: productDetails.plan || newOrder.planName,
                    amount: costNGN,
                    paymentReference: paymentReference
                },
                confirmationNumber: paymentReference,     
                targetNumber: mobileNumber || newOrder.metadata?.targetNumber || "N/A",
                country: coverageCountry || newOrder.metadata?.country || "N/A", 
                activationCode: deliveryCode,     
                instructions: deliveryInstructions,  
                mainBalanceUsed: newOrder.mainBalanceUsed || 0,
                bonusBalanceUsed: newOrder.bonusBalanceUsed || 0,
                metadata: newOrder.metadata,
                purchaseDate: newOrder.createdAt || new Date()
            }).catch(err => console.error("📧 Customer Email Error:", err.message));
        }

        if (isManual) { 
            try {
                await sendAdminNotification({
                    type: itemType,
                    email: user.email,
                    product: productDetails.name,
                    amount: `₦${costNGN.toLocaleString()}`,
                    reference: paymentReference,
                    target: mobileNumber || newOrder.metadata?.targetNumber || newOrder.metadata?.activationEmail || 'N/A',
                    country: coverageCountry || newOrder.metadata?.country || 'N/A', 
                    metadata: newOrder.metadata,
                    orderSpecifics: orderSpecifics,
                    planName: productDetails.plan || newOrder.planName || 'Standard'
                });
                console.log("✅ Admin notification sent successfully");
            } catch (err) {
                console.error("📧 Admin Notification Error:", err.message);
            }
        }

        return res.json({ 
            success: true, 
            message: isManual 
                ? "Request submitted! Our team is processing your order." 
                : "Purchase successful!",
            balance: updatedUser.balance,
            bonusBalance: updatedUser.bonusBalance,
            order: newOrder 
        });

    } catch (err) {
        console.error("Wallet Purchase Error:", err);
        return res.status(500).json({ success: false, message: "Internal server error." });
    }
}

const sendAdminNotification = async (orderData) => {
    // 1. Create Transporter inside the function
    const adminTransporter = nodemailer.createTransport({
        service: 'gmail',
        pool: true,
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASS
        }
    });

    const { type, email, amount, product, reference, target, metadata, orderSpecifics, country } = orderData;
    
    // Styles
    const labelStyle = "font-size: 11px; color: #64748b; text-transform: uppercase; font-weight: bold; margin-bottom: 2px; display: block;";
    const valueStyle = "font-size: 13px; color: #1e293b; font-weight: 600;";
    
    let specificDetailsHtml = '';

    // Normalize type for comparison
    const orderType = type ? type.toLowerCase() : "";

  // --- RDP DETAILS ---
// --- RDP DETAILS ---
if (orderType === "rdp") {
    // 1. Extract values from root orderData (priority) or nested metadata
    const ram = orderData.ram || metadata?.ram || 'N/A';
    const os = orderData.os || metadata?.osChoice || 'Windows Server';
    const cpu = orderData.cpu || metadata?.cpu || 'N/A';
    const storage = orderData.storage || metadata?.storage || 'N/A';
    const net = orderData.net || metadata?.net || '1Gbps';
    
    // 2. Explicitly grab the extras
    const extraCPU = parseInt(orderData.extraCPU || metadata?.extraCPU || 0);
    const extraStorage = parseInt(orderData.extraStorage || metadata?.extraStorage || 0);

    specificDetailsHtml = `
        <div style="background: #f8fafc; padding: 12px; border: 1px solid #cbd5e1; border-radius: 8px; margin: 12px 0;">
            <p style="font-size: 12px; margin:0 0 10px 0; color: #0F54C6; border-bottom: 1px solid #cbd5e1; padding-bottom: 5px;">
                <b>🖥️ RDP PROVISIONING SPECS</b>
            </p>
            <table width="100%" cellspacing="0" cellpadding="0">
                <tr>
                    <td width="50%" style="padding-bottom: 10px;">
                        <span style="${labelStyle}">OS</span>
                        <span style="${valueStyle}">${os}</span>
                    </td>
                    <td width="50%" style="padding-bottom: 10px;">
                        <span style="${labelStyle}">RAM</span>
                        <span style="${valueStyle}">${ram}</span>
                    </td>
                </tr>
                <tr>
                    <td width="50%" style="padding-bottom: 10px;">
                        <span style="${labelStyle}">Base CPU</span>
                        <span style="${valueStyle}">${cpu}</span>
                        ${extraCPU > 0 ? `<br><span style="color: #dc2626; font-size: 11px; font-weight: bold;">🔥 +${extraCPU} EXTRA CORES</span>` : ''}
                    </td>
                    <td width="50%" style="padding-bottom: 10px;">
                        <span style="${labelStyle}">Base Storage</span>
                        <span style="${valueStyle}">${storage}</span>
                        ${extraStorage > 0 ? `<br><span style="color: #dc2626; font-size: 11px; font-weight: bold;">🔥 +${extraStorage}GB EXTRA</span>` : ''}
                    </td>
                </tr>
                <tr>
                    <td colspan="2" style="border-top: 1px dashed #cbd5e1; padding-top: 10px;">
                        <span style="${labelStyle}">Network Speed</span>
                        <span style="${valueStyle}">${net}</span>
                    </td>
                </tr>
            </table>
            <div style="margin-top: 10px; background: #fffbeb; border: 1px solid #fef3c7; padding: 8px; border-radius: 4px;">
                <p style="font-size: 11px; color: #92400e; margin: 0;">
                    <b>Admin Note:</b> Please ensure the extra resources are added to the instance before sending credentials.
                </p>
            </div>
        </div>`;
}
    else if (orderType === "esim_refill") {
        specificDetailsHtml = `
            <div style="background: #f0fdf4; padding: 10px; border: 1px solid #bbf7d0; border-radius: 8px; margin: 12px 0;">
                <p style="font-size: 12px; margin:0 0 8px 0; color: #166534;"><b>📲 REFILL DETAILS</b></p>
                <table width="100%" cellspacing="0" cellpadding="2">
                    <tr>
                        <td width="50%"><span style="${labelStyle}">Target Number</span><span style="${valueStyle}">${target || 'N/A'}</span></td>
                        <td width="50%"><span style="${labelStyle}">Carrier</span><span style="${valueStyle}">${product || 'eSIM'}</span></td>
                    </tr>
                    <tr>
                        <td width="50%" style="padding-top:8px;"><span style="${labelStyle}">Country</span><span style="${valueStyle}">${country || 'N/A'}</span></td>
                        <td width="50%" style="padding-top:8px;"><span style="${labelStyle}">Plan</span><span style="${valueStyle}">${orderData.planName || 'Standard'}</span></td>
                    </tr>
                </table>
            </div>`;
    }
    // --- ESIM ACTIVATION DETAILS (NEW) ---
    else if (orderType === "esim_activation") {
        specificDetailsHtml = `
            <div style="background: #fff7ed; padding: 10px; border: 1px solid #ffedd5; border-radius: 8px; margin: 12px 0;">
                <p style="font-size: 12px; margin:0 0 8px 0; color: #9a3412;"><b>📶 ACTIVATION REQUEST</b></p>
                <table width="100%" cellspacing="0" cellpadding="2">
                    <tr>
                        <td width="50%"><span style="${labelStyle}">Subscriber</span><span style="${valueStyle}">${metadata?.firstName || ''} ${metadata?.lastName || ''}</span></td>
                        <td width="50%"><span style="${labelStyle}">Device</span><span style="${valueStyle}">${target || 'N/A'}</span></td>
                    </tr>
                    <tr>
                        <td colspan="2" style="padding-top:8px;">
                            <span style="${labelStyle}">Address</span>
                            <span style="${valueStyle}">${metadata?.address || 'N/A'}, ${metadata?.zip || ''}</span>
                        </td>
                    </tr>
                    <tr>
                        <td width="50%" style="padding-top:8px;"><span style="${labelStyle}">Carrier</span><span style="${valueStyle}">${product || 'N/A'}</span></td>
                        <td width="50%" style="padding-top:8px;"><span style="${labelStyle}">Type</span><span style="${valueStyle}">${metadata?.activationType || 'Prepaid'}</span></td>
                    </tr>
                </table>
            </div>`;
    }

    const htmlContent = `
        <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, sans-serif; max-width: 450px; margin: auto; border: 1px solid #e2e8f0; border-radius: 12px; overflow: hidden; background: #ffffff;">
            <div style="background: #0F54C6; padding: 15px; text-align: center;">
                <img src="https://imgur.com/8YeZgfx.png" alt="SMSGlobe" width="100">
            </div>
            
            <div style="padding: 20px;">
                <h3 style="color: #0F54C6; font-size: 16px; margin: 0 0 15px 0; text-align: center;">🚨 New ${type.replace('_', ' ')} Order</h3>
                
                <div style="border-bottom: 1px solid #f1f5f9; padding-bottom: 10px; margin-bottom: 10px;">
                    <span style="${labelStyle}">Customer Email</span>
                    <span style="${valueStyle}">${email}</span>
                </div>

                <div style="display: flex; justify-content: space-between; margin-bottom: 10px;">
                    <div style="width: 48%;">
                        <span style="${labelStyle}">Amount</span>
                        <span style="font-size: 15px; color: #101828; font-weight: 800;">${amount}</span>
                    </div>
                    <div style="width: 48%;">
                        <span style="${labelStyle}">Ref</span>
                        <code style="font-size: 11px; background:#f1f5f9; padding:2px 4px; border-radius:4px;">${reference}</code>
                    </div>
                </div>

                ${specificDetailsHtml}

                <div style="text-align: center; margin-top: 20px;">
                    <a href="https://smsglobe.netlify.app/admin" 
                       style="background: #0F54C6; color: white; padding: 12px 20px; text-decoration: none; border-radius: 6px; font-size: 13px; font-weight: bold; display: inline-block; width: 80%;">
                        Complete Order
                    </a>
                </div>
            </div>
            
            <div style="background: #f8fafc; padding: 12px; text-align: center;">
                <p style="font-size: 10px; color: #94a3b8; margin: 0;">Priority System Alert &bull; SMSGlobe Admin</p>
            </div>
        </div>
    `;

    try {
        await adminTransporter.sendMail({
            from: `"SMSGlobe Alert" <${process.env.EMAIL_USER}>`,
            to: process.env.ADMIN_EMAIL,
            subject: `🚨 ${type.toUpperCase()}: ${amount} from ${email}`,
            html: htmlContent
        });
        console.log(`Admin alert sent for ${type}`);
    } catch (error) {
        console.error("Admin Mail Error:", error.message);
    }
};


const sendDeliveryEmail = async (userEmail, credentials) => {
    const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASS
        }
    });

   const type = (credentials.type || credentials.productType || "").trim();
const upperType = type.toUpperCase(); // Define this to use for the checks below

// 2. Format the Date
const rawDate = credentials.purchaseDate || new Date();
const purchaseDate = new Date(rawDate).toLocaleString('en-NG', {
    dateStyle: 'medium',
    timeStyle: 'short'
});

if (!type) {
    console.error("📧 Email Error: No product type provided in credentials object.");
    return;
}

const isVPN = upperType === "VPN";
const isRDP = upperType === "RDP";
const isProxy = upperType === "PROXY" || upperType === "PREMIUM PROXY"; 
const isESIM_Refill = type === "eSIM_Refill";       
const isESIM_Activation = type === "eSIM_Activation"; 

    let subject, headerTitle, subHeader;

    // 2. Determine Subject and Headers
    if (isRDP) {
        subject = "🖥️ Your RDP Server is Ready!";
        headerTitle = "Server Provisioned!";
        subHeader = "Your high-performance RDP access details are below.";
    } else if (isVPN) {
        subject = "🔑 Your VPN Access Credentials";
        headerTitle = "VPN Activated!";
        subHeader = "Your Premium VPN Access is ready.";
    } else if (isESIM_Activation) {
        subject = "✅ eSIM Activated Successfully";
        headerTitle = "Activation Complete!";
        subHeader = "Your eSIM profile is now active and ready for use.";
    } else if (isESIM_Refill) {
        subject = "✅ eSIM Refill Confirmed";
        headerTitle = "Refill Successful!";
        subHeader = "Your eSIM has been successfully topped up.";
    } else {
        subject = `🌐 Your ${type} Activation Details`;
        headerTitle = `${type} Ready! 🌐`;
        subHeader = `Your ${type} details are provided below.`;
    }
    
    let dataTableHtml = '';
if (isProxy) {
    const displayCode = credentials.activationCode || 
                        (credentials.activationCodes && credentials.activationCodes.length > 0 ? credentials.activationCodes[0] : 'PENDING');
    const displayInstructions = credentials.instructions || 'Follow the dashboard instructions to activate.';    
    const displayService = credentials.name || credentials.nodeName || 'Proxy Service';
    const displayPlan = credentials.category || credentials.planName || 'Standard Plan';
        const displayAmount = Number(credentials.amount || 0).toLocaleString();
    const displayRef = credentials.paymentReference || credentials._id || 'N/A';

    dataTableHtml = `
        <tr>
            <td class="mobile-full" width="50%" valign="top" style="padding-bottom: 15px;">
                <span style="font-size: 9px; color: #667085; text-transform: uppercase; font-weight: bold;">Service</span><br>
                <strong style="font-size: 13px; color: #0F54C6;">${displayService}</strong>
            </td>
            <td class="mobile-full" width="50%" valign="top" style="text-align: right; padding-bottom: 15px;">
                <span style="font-size: 9px; color: #667085; text-transform: uppercase; font-weight: bold;">Category</span><br>
                <strong style="font-size: 13px; color: #101828;">${displayPlan}</strong>
            </td>
        </tr>
        <tr>
            <td class="mobile-full" width="50%" valign="top" style="padding-bottom: 15px;">
                <span style="font-size: 9px; color: #667085; text-transform: uppercase; font-weight: bold;">Purchase Date</span><br>
                <strong style="font-size: 11px; color: #101828;">${new Date().toLocaleDateString()}</strong>
            </td>
            <td class="mobile-full" width="50%" valign="top" style="text-align: right; padding-bottom: 15px;">
                <span style="font-size: 9px; color: #667085; text-transform: uppercase; font-weight: bold;">Amount Paid</span><br>
                <strong style="font-size: 13px; color: #101828;">₦${displayAmount}</strong>
            </td>
        </tr>
        <tr>
            <td colspan="2" style="border-top: 1px solid #D1E0FF; padding-top: 20px; text-align: center;">
                <div style="background: #f8faff; border: 1px dashed #0F54C6; padding: 20px; border-radius: 12px;">
                    <span style="font-size: 10px; color: #0F54C6; text-transform: uppercase; font-weight: 800; letter-spacing: 1px;">Your Activation Code</span><br>
                    <div style="margin-top: 10px; background: #ffffff; padding: 10px; border-radius: 8px; display: inline-block; border: 1px solid #e2e8f0;">
                        <strong style="font-size: 22px; font-family: 'Courier New', monospace; color: #101828; letter-spacing: 2px;">
                            ${displayCode}
                        </strong>
                    </div>
                    <p style="font-size: 11px; color: #E11D48; margin-top: 12px; font-weight: bold; text-transform: uppercase;">
                        ${displayInstructions}
                    </p>
                    <p style="font-size: 10px; color: #667085; margin-top: 5px;">
                        Use this code to activate your <strong>${displayService}</strong> subscription.
                    </p>
                </div>
            </td>
        </tr>
        <tr>
            <td colspan="2" style="padding-top: 15px; text-align: center;">
                <span style="font-size: 9px; color: #667085; text-transform: uppercase;">Transaction ID:</span><br>
                <code style="font-size: 10px; color: #98A2B3;">${displayRef}</code>
            </td>
        </tr>
    `;
}

if (isRDP) {
    // 1. Extract Hardware Values (Root Level priority)
    const ramValue = credentials.ram || credentials.metadata?.ram || "4GB";
    const osValue = credentials.os || credentials.osChoice || credentials.metadata?.osChoice || 'Windows Server';
    const netValue = credentials.net || credentials.metadata?.net || '1Gbps';    
    const extraCPU = parseInt(credentials.extraCPU || credentials.metadata?.extraCPU || 0);
    const extraStorage = parseInt(credentials.extraStorage || credentials.metadata?.extraStorage || 0);
    const baseCPU = credentials.cpu || credentials.metadata?.cpu || "2 Cores";
    const baseStorage = credentials.storage || credentials.metadata?.storage || "60GB SSD";
    const displayCpu = extraCPU > 0 ? `${baseCPU} (+${extraCPU} vCPU)` : baseCPU;
    const displayStorage = extraStorage > 0 ? `${baseStorage} (+${extraStorage}GB)` : baseStorage;

    // 5. Build the HTML
    dataTableHtml = `
        <tr>
            <td class="mobile-full" width="50%" valign="top" style="padding-bottom: 15px;">
                <span style="font-size: 9px; color: #667085; text-transform: uppercase; font-weight: bold;">Confirmation ID</span><br>
                <strong style="font-size: 13px; font-family: 'Courier New', monospace; color: #0F54C6;">
                    ${credentials.confirmationNumber || 'N/A'}
                </strong>
            </td>
            <td class="mobile-full" width="50%" valign="top" style="text-align: right; padding-bottom: 15px;">
                <span style="font-size: 9px; color: #667085; text-transform: uppercase; font-weight: bold;">Operating System</span><br>
                <strong style="font-size: 13px; color: #101828;">${osValue}</strong>
            </td>
        </tr>

        <tr>
            <td colspan="2" style="background-color: #f8fafc; border: 1px solid #e2e8f0; border-radius: 12px; padding: 15px; margin-bottom: 20px;">
                <div style="margin-bottom: 10px; border-bottom: 1px solid #e2e8f0; padding-bottom: 5px;">
                    <span style="font-size: 10px; color: #0F54C6; text-transform: uppercase; font-weight: bold;">Login Credentials</span>
                </div>
                <table width="100%" cellspacing="0" cellpadding="0">
                    <tr>
                        <td width="50%" style="padding-bottom: 8px;">
                            <span style="font-size: 9px; color: #667085; text-transform: uppercase;">IP Address:</span><br>
                            <strong style="font-size: 12px; font-family: monospace;">${credentials.ipAddress || 'Check Dashboard'}</strong>
                        </td>
                        <td width="50%" style="padding-bottom: 8px;">
                            <span style="font-size: 9px; color: #667085; text-transform: uppercase;">Port:</span><br>
                            <strong style="font-size: 12px; font-family: monospace;">${credentials.port || '3389'}</strong>
                        </td>
                    </tr>
                    <tr>
                        <td>
                            <span style="font-size: 9px; color: #667085; text-transform: uppercase;">Username:</span><br>
                            <strong style="font-size: 12px; font-family: monospace;">${credentials.rdpUsername || 'Administrator'}</strong>
                        </td>
                        <td>
                            <span style="font-size: 9px; color: #667085; text-transform: uppercase;">Password:</span><br>
                            <strong style="font-size: 12px; font-family: monospace; color: #d946ef;">${credentials.rdpPassword || '********'}</strong>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>

        <tr>
            <td colspan="2" style="padding-top: 15px;">
                <table width="100%" cellspacing="0" cellpadding="0">
                    <tr>
                        <td width="33%" valign="top">
                            <span style="font-size: 9px; color: #667085; text-transform: uppercase; font-weight: bold;">RAM</span><br>
                            <strong style="font-size: 12px; color: #101828;">${ramValue}</strong>
                        </td>
                        <td width="33%" valign="top" style="text-align: center;">
                            <span style="font-size: 9px; color: #667085; text-transform: uppercase; font-weight: bold;">CPU</span><br>
                            <strong style="font-size: 12px; color: #101828;">${displayCpu}</strong>
                        </td>
                        <td width="33%" valign="top" style="text-align: right;">
                            <span style="font-size: 9px; color: #667085; text-transform: uppercase; font-weight: bold;">Storage</span><br>
                            <strong style="font-size: 12px; color: #101828;">${displayStorage}</strong>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>

        <tr>
            <td colspan="2" style="border-top: 1px dashed #e2e8f0; padding-top: 10px; margin-top: 10px;">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div>
                        <span style="font-size: 9px; color: #667085; text-transform: uppercase; font-weight: bold;">Network Speed</span><br>
                        <strong style="font-size: 12px; color: #101828;">${netValue}</strong>
                    </div>
                    
                    ${credentials.receiptUrl ? `
                    <div style="text-align: right;">
                        <a href="${credentials.receiptUrl}" target="_blank" 
                           style="display: inline-block; padding: 8px 12px; background-color: #0F54C6; color: #ffffff; text-decoration: none; border-radius: 8px; font-size: 10px; font-weight: bold; text-transform: uppercase;">
                           View Receipt
                        </a>
                    </div>
                    ` : ''}
                </div>
            </td>
        </tr>
    `;
}
else if (isVPN) {
    // 1. Data Extraction
    const vpnCreds = credentials.vpnCredentials || {};        
    
    // Normalize the target device (Phone vs PC)
    const targetType = (credentials.targetDevice || credentials.deviceType || "Phone").toLowerCase(); 
    
    // Extract potential credential values
    const mUser = vpnCreds.username || credentials.username || "";
    const mPass = vpnCreds.password || credentials.password || "";    
    const pcUser = credentials.pcUsername || "";
    const pcPass = credentials.pcPassword || "";    
    const aCode = credentials.activationCode || "";    
    const adminInstructions = credentials.instructions || "Follow the setup guide in your dashboard.";

    // 2. Strict Logic Flags
    const isPC = targetType === 'pc';
    const isPhone = targetType === 'phone' || targetType === "";

    // Determine what to display based on the device intent
    const showCode = isPC && !!(aCode && aCode !== "N/A");
    
    // PC section: only show if device is PC and data exists
    const showPC = isPC && !!(pcUser || mUser) && !showCode; 
    
    // Mobile section: only show if device is Phone and data exists
    const showMobile = isPhone && !!(mUser && mUser !== "N/A");

    // Dynamic Labeling
    const label = isPC ? "PC" : "Mobile";
    const displayUser = isPC ? (pcUser || mUser) : mUser;
    const displayPass = isPC ? (pcPass || mPass) : mPass;

    // 3. Build HTML
    dataTableHtml = `
        <tr>
            <td colspan="2" valign="top" style="padding-bottom: 20px;">
                <div style="background: #f9fafb; border: 1px solid #eaecf0; padding: 12px; border-radius: 8px; text-align: center;">
                    <span style="font-size: 10px; color: #667085; text-transform: uppercase; font-weight: 800; letter-spacing: 0.5px;">Connection Limit</span><br>
                    <strong style="font-size: 15px; color: #0F54C6;">${credentials.deviceLimit || 1} Device(s) Allowed</strong>
                </div>
            </td>
        </tr>
        
        ${showCode ? `
        <tr>
            <td style="padding: 12px; border-bottom: 1px solid #f2f4f7;"><strong>Activation Code:</strong></td>
            <td style="padding: 12px; border-bottom: 1px solid #f2f4f7; text-align:right;">
                <span style="font-family: monospace; color: #0F54C6; background: #f0f5ff; padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 14px;">
                    ${aCode}
                </span>
            </td>
        </tr>` : ''}

        ${(showMobile || showPC) ? `
        <tr>
            <td style="padding: 10px; border-bottom: 1px solid #eee;"><strong>${label} Username:</strong></td>
            <td style="padding: 10px; border-bottom: 1px solid #eee; text-align:right; color: #101828;">${displayUser}</td>
        </tr>
        <tr>
            <td style="padding: 10px; border-bottom: 1px solid #eee;"><strong>${label} Password:</strong></td>
            <td style="padding: 10px; border-bottom: 1px solid #eee; text-align:right; color: #101828;">${displayPass}</td>
        </tr>` : ''}

        <tr>
            <td colspan="2" style="padding-top: 20px;">
                <div style="background: #FFF5F5; border-left: 4px solid #E11D48; padding: 15px; border-radius: 4px;">
                    <span style="font-size: 10px; color: #E11D48; text-transform: uppercase; font-weight: bold;">Setup Instructions:</span>
                    <p style="margin: 5px 0 0 0; font-size: 12px; color: #101828; line-height: 1.5; font-weight: 500;">
                        ${adminInstructions}
                    </p>
                </div>
            </td>
        </tr>
    `;
}

 else if (isESIM_Activation) {
        const confNo = credentials.confirmationNumber || credentials.activationCode;
        const meta = credentials.metadata || {};
        
        // Map Subscriber Info from Metadata
        const fName = meta.firstName || credentials.firstName || "";
        const lName = meta.lastName || credentials.lastName || "";
        const subscriberName = `${fName} ${lName}`.trim() || "Customer";
        
        const displayEmail = meta.activationEmail || meta.email || credentials.email || 'N/A';
        const displayAddress = meta.address || credentials.address || 'Digital Delivery';
        const displayZip = meta.zip || credentials.zip || 'N/A';
        const displayType = meta.activationType || credentials.activationType || 'Prepaid';
        
        // Handle Receipt Link
        const receiptUrl = credentials.receiptUrl || meta.receiptUrl;
        let receiptSection = "";

        if (receiptUrl) {
            receiptSection = `
                <tr>
                    <td colspan="2" style="padding-top: 10px; padding-bottom: 20px; text-align: center;">
                        <a href="${receiptUrl}" target="_blank" style="display: inline-block; background-color: #0F54C6; color: #ffffff; padding: 12px 25px; border-radius: 8px; text-decoration: none; font-weight: bold; font-size: 13px; shadow: 0 4px 6px rgba(0,0,0,0.1);">
                            📄 Download Official Receipt
                        </a>
                        <p style="font-size: 10px; color: #667085; margin-top: 8px;">Valid for official records and reimbursements</p>
                    </td>
                </tr>
            `;
        }

        dataTableHtml = `
            ${receiptSection}
            <tr>
                <td class="mobile-full" width="50%" valign="top" style="padding-bottom: 15px;">
                    <span style="font-size: 9px; color: #667085; text-transform: uppercase; font-weight: bold;">Carrier</span><br>
                    <strong style="font-size: 13px; color: #0F54C6;">${credentials.nodeName || 'Global eSIM'}</strong>
                </td>
                <td class="mobile-full" width="50%" valign="top" style="text-align: right; padding-bottom: 15px;">
                    <span style="font-size: 9px; color: #667085; text-transform: uppercase; font-weight: bold;">Device Model</span><br>
                    <strong style="font-size: 13px; color: #101828;">${credentials.targetNumber || 'N/A'}</strong>
                </td>
            </tr>
            <tr>
                <td class="mobile-full" width="50%" valign="top" style="padding-bottom: 15px;">
                    <span style="font-size: 9px; color: #667085; text-transform: uppercase; font-weight: bold;">Subscription Plan</span><br>
                    <strong style="font-size: 13px; color: #101828;">${credentials.planName || 'Standard Activation'}</strong>
                </td>
                <td class="mobile-full" width="50%" valign="top" style="text-align: right; padding-bottom: 15px;">
                    <span style="font-size: 9px; color: #667085; text-transform: uppercase; font-weight: bold;">Amount Paid</span><br>
                    <strong style="font-size: 13px; color: #101828;">₦${Number(credentials.amount || 0).toLocaleString()}</strong>
                </td>
            </tr>
            <tr>
                <td colspan="2" style="border-top: 1px solid #f2f4f7; padding-top: 15px; padding-bottom: 15px;">
                    <span style="font-size: 9px; color: #667085; text-transform: uppercase; font-weight: bold;">Subscriber Details</span><br>
                    <div style="font-size: 12px; color: #344054; line-height: 1.6; background: #f9fafb; padding: 12px; border-radius: 8px; margin-top: 5px; border: 1px solid #eaecf0;">
                        <strong style="color: #667085;">Name:</strong> ${subscriberName}<br>
                        <strong style="color: #667085;">Email:</strong> ${displayEmail}<br>
                        <strong style="color: #667085;">Address:</strong> ${displayAddress}<br>
                        <strong style="color: #667085;">ZIP:</strong> ${displayZip} | <strong style="color: #667085;">Type:</strong> ${displayType}
                    </div>
                </td>
            </tr>
            <tr>
                <td colspan="2" style="border-top: 1px solid #D1E0FF; padding-top: 15px; text-align: center;">
                    <div style="background: #ECFDF3; border: 1px solid #ABEFC6; padding: 15px; border-radius: 8px;">
                        <span style="font-size: 9px; color: #067647; text-transform: uppercase; font-weight: bold;">Confirmation Number</span><br>
                        <strong style="font-size: 20px; font-family: 'Courier New', monospace; color: #101828; letter-spacing: 1px;">${confNo || 'SUCCESSFUL'}</strong>
                    </div>
                </td>
            </tr>`;
    }
   else if (isESIM_Refill) {
    const confNo = credentials.confirmationNumber || credentials.confNo;
    const rawAmount = String(credentials.amount || 0).replace(/[^0-9.-]+/g, "");
    const displayAmount = Number(rawAmount) || 0;
    const displayCountry = credentials.country || (credentials.target && credentials.target.country) || 'N/A';
    const displayTarget = credentials.targetNumber || (credentials.target && credentials.target.number) || 'N/A';

    // Conditional Receipt Button
    let receiptBtn = '';
    if (credentials.receiptUrl) {
        receiptBtn = `
            <div style="margin-top: 15px;">
                <a href="${credentials.receiptUrl}" 
                   style="display: inline-block; padding: 12px 24px; background-color: #0F54C6; color: #ffffff; text-decoration: none; border-radius: 8px; font-size: 11px; font-weight: bold; text-transform: uppercase; letter-spacing: 0.5px;">
                   View Transaction Receipt
                </a>
            </div>`;
    }

    dataTableHtml = `
        <tr>
            <td class="mobile-full" width="50%" valign="top" style="padding-bottom: 15px;">
                <span style="font-size: 9px; color: #667085; text-transform: uppercase; font-weight: bold;">Carrier</span><br>
                <strong style="font-size: 13px; color: #0F54C6;">${credentials.nodeName || 'eSIM Carrier'}</strong>
            </td>
            <td class="mobile-full" width="50%" valign="top" style="text-align: right; padding-bottom: 15px;">
                <span style="font-size: 9px; color: #667085; text-transform: uppercase; font-weight: bold;">Target Number</span><br>
                <strong style="font-size: 13px; font-family: 'Courier New', monospace; color: #101828;">${displayTarget}</strong>
            </td>
        </tr>
        <tr>
            <td class="mobile-full" width="50%" valign="top" style="padding-bottom: 15px;">
                <span style="font-size: 9px; color: #667085; text-transform: uppercase; font-weight: bold;">Country</span><br>
                <strong style="font-size: 13px; color: #101828;">${displayCountry}</strong>
            </td>
            <td class="mobile-full" width="50%" valign="top" style="text-align: right; padding-bottom: 15px;">
                <span style="font-size: 9px; color: #667085; text-transform: uppercase; font-weight: bold;">Price Paid</span><br>
                <strong style="font-size: 13px; color: #101828;">₦${displayAmount.toLocaleString()}</strong>
            </td>
        </tr>
        <tr>
            <td colspan="2" style="border-top: 1px solid #D1E0FF; padding-top: 15px; text-align: center;">
                <div style="background: #ECFDF3; border: 1px solid #ABEFC6; padding: 15px; border-radius: 8px;">
                    <span style="font-size: 9px; color: #067647; text-transform: uppercase; font-weight: bold;">Confirmation Number</span><br>
                    <strong style="font-size: 20px; font-family: 'Courier New', monospace; color: #101828; letter-spacing: 1px;">${confNo || 'SUCCESSFUL'}</strong>
                </div>
                ${receiptBtn}
            </td>
        </tr>`;
}
else {
        // Generic fallback
        dataTableHtml = `
            <tr>
                <td class="mobile-full" width="50%" valign="top">
                    <span style="font-size: 9px; color: #667085; text-transform: uppercase; font-weight: bold;">Product</span><br>
                    <strong style="font-size: 14px; color: #0F54C6;">${credentials.nodeName || 'Service'}</strong>
                </td>
                <td class="mobile-full" width="50%" valign="top" style="text-align: right;">
                    <span style="font-size: 9px; color: #667085; text-transform: uppercase; font-weight: bold;">Price Paid</span><br>
                    <strong style="font-size: 14px; color: #101828;">₦${Number(credentials.amount || 0).toLocaleString()}</strong>
                </td>
            </tr>
            <tr>
                <td colspan="2" style="padding-top: 10px;">
                    <span style="font-size: 9px; color: #667085; text-transform: uppercase; font-weight: bold;">Confirmation Number</span><br>
                    <strong style="font-size: 14px; font-family: 'Courier New', monospace; color: #101828;">
                        ${credentials.confirmationNumber || credentials.activationCode || 'N/A'}
                    </strong>
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

const emailAttachments = [];
    if (credentials.receiptUrl) {
        const extension = credentials.receiptUrl.split('.').pop().toLowerCase().split('?')[0]; // Handle query params
        emailAttachments.push({
            filename: `SMSGlobe_Receipt_${credentials.confirmationNumber || 'Order'}.${extension}`,
            path: credentials.receiptUrl
        });
    }

    try {
        await transporter.sendMail({
            from: `"SMSGlobe Support" <${process.env.EMAIL_USER}>`,
            to: userEmail,
            subject: `${subject} - SMSGlobe`,
            html: htmlContent,
            attachments: emailAttachments // Physical file attachment
        });
        console.log(`Delivery email sent to: ${userEmail}`);
    } catch (error) {
        console.error("Nodemailer Error:", error);
    }
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
        // We exclude activationCodes from the list view for security/performance
        // But we include activationCode (singular) if you still want to see the "Current" one
        const proxies = await Proxy.find({}).sort({ createdAt: -1 });
        return res.json({ success: true, proxies });
    } catch (err) {
        return res.status(500).json({ success: false, message: "Fetch failed" });
    }
}

// 3. ADD Proxy (Vending Machine Logic)
async function handleAddProxy(req, res) {
    try {
        const { name, category, imageUrl, activationCode, activationCodes, instructions, plans, stock } = req.body;

        // Clean and parse the plans
        let formattedPlans = [];
        if (plans && Array.isArray(plans)) {
            formattedPlans = plans.map(p => ({
                ip_count: parseInt(p.ip_count) || 0,
                price: Math.round(parseFloat(p.price)) || 0 
            }));
        }

        // Logic: Use the array length for stock if codes were uploaded
        const finalCodes = Array.isArray(activationCodes) ? activationCodes : [];
        const finalStock = finalCodes.length > 0 ? finalCodes.length : (parseInt(stock) || 0);

        const newProxy = new Proxy({
            name,
            category: category || 'Standard', 
            imageUrl,
            // Single code for backward compatibility
            activationCode: activationCode || (finalCodes.length > 0 ? finalCodes[0] : ""),
            // The full array for the vending machine
            activationCodes: finalCodes,
            instructions,
            stock: finalStock,
            plans: formattedPlans
        });

        await newProxy.save();
        return res.json({ success: true, message: "Proxy Package Deployed with " + finalStock + " codes" });
    } catch (err) {
        console.error("Add Proxy Error:", err);
        return res.status(500).json({ success: false, message: "Deployment failed" });
    }
}

// 4. UPDATE Proxy (With Bulk Code Support)
async function handleUpdateProxy(req, res) {
    try {
        const { proxyId, plans, stock, activationCodes, ...restOfData } = req.body;

        // Prepare the update object
        const updatePayload = { ...restOfData };

        // Handle plans parsing
        if (plans && Array.isArray(plans)) {
            updatePayload.plans = plans.map(p => ({
                ip_count: parseInt(p.ip_count) || 0,
                price: Math.round(parseFloat(p.price)) || 0 
            }));
        }

if (Array.isArray(activationCodes)) {
    updatePayload.activationCodes = activationCodes;
    updatePayload.stock = activationCodes.length;
    
    updatePayload.activationCode = activationCodes.length > 0 ? activationCodes[0] : "";
} else {
    updatePayload.stock = parseInt(stock) || 0;
}
        const updated = await Proxy.findByIdAndUpdate(
            proxyId, 
            { $set: updatePayload }, 
            { new: true }
        );
        
        if (!updated) return res.status(404).json({ success: false, message: "Proxy not found" });

        return res.json({ success: true, message: "Proxy Package Updated successfully" });
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
    // 1. Destructure data (Added coverageCountry from frontend)
    const { email, carrierName, mobileNumber, planAmount, productImage, useBonus, coverageCountry, carrierId } = req.body;

    if (!email || !carrierName || !mobileNumber || !planAmount) {
        return res.status(400).json({ success: false, message: "Missing required eSIM data" });
    }

    try {
        const user = await User.findOne({ email: email.toLowerCase() });
        if (!user) return res.status(404).json({ success: false, message: "User not found" });
        const finalAmountNGN = Math.round(Number(planAmount.toString().replace(/[^0-9]/g, "")));

        // 3. Balance Deduction Logic
        let remainingToPay = finalAmountNGN;
        let bonusUsed = 0;
        let mainUsed = 0;
        const canUseBonus = useBonus && (user.hasDeposited || user.ngn > 0);

        if (canUseBonus && user.bonusNGN > 0) {
            bonusUsed = Math.min(user.bonusNGN, remainingToPay);
            remainingToPay -= bonusUsed;
        }

        if (remainingToPay > user.ngn) {
            return res.status(400).json({ success: false, message: "Insufficient wallet balance" });
        }

        mainUsed = remainingToPay;
        user.ngn -= mainUsed;
        user.bonusNGN -= bonusUsed;
        await user.save();

        // 5. Create Unified Order Record
        const refId = `ESIM-${Date.now()}-${user._id.toString().slice(-4)}`;
        
      const newOrder = await Order.create({
    userEmail: email.toLowerCase(),
    userId: user._id,
    productType: 'eSIM_Refill', 
    nodeName: carrierName, 
    planName: `₦${finalAmountNGN.toLocaleString()}`, 
    amount: finalAmountNGN,
    currency: 'NGN',
    mainBalanceUsed: mainUsed,
    bonusBalanceUsed: bonusUsed,
    paymentReference: refId,
    status: 'pending',

    // NESTED OBJECTS (For showReceipt order.target.number)
    carrier: {
        id: carrierId || 'manual',
        name: carrierName,
        image: productImage
    },
    target: {
        number: mobileNumber,
        country: coverageCountry || 'Global' 
    },

    // TOP-LEVEL HELPERS (For showReceipt order.targetNumber)
    targetNumber: mobileNumber,
    country: coverageCountry || 'Global'
});

        await Transaction.create({
            userId: user._id,
            type: 'debit',
            purpose: 'purchase',
            amountNGN: finalAmountNGN,
            status: 'successful',
            reference: refId,
            paymentMethod: 'wallet_combined',
            balanceBefore: user.ngn + mainUsed,
            balanceAfter: user.ngn,
            bonusBefore: user.bonusNGN + bonusUsed,
            bonusAfter: user.bonusNGN,
            metadata: { 
                orderId: newOrder._id, 
                product: carrierName 
            }
        });

        return res.status(201).json({ 
            success: true, 
            message: "Refill ordered successfully. Admin notified.", 
            order: newOrder,
            ref: refId
        });

    } catch (err) {
        console.error("eSIM Wallet Purchase Error:", err);
        return res.status(500).json({ success: false, message: "Transaction failed. Please contact support." });
    }
}

async function getEsimRefills(req, res) {
    try {
        const refills = await Order.find({ productType: 'eSIM_Refill' })
            .sort({ createdAt: -1 })
            .limit(100);

        const formattedRefills = refills.map(refill => ({
            paymentReference: refill.paymentReference,
            createdAt: refill.createdAt,
            userEmail: refill.userEmail,
            fullName: refill.fullName || "Customer",
            amountNGN: `₦${Number(refill.amount).toLocaleString()}`, 
            status: refill.status || '',   
            receiptUrl: refill.receiptUrl || null,         
            targetNumber: refill.targetNumber || (refill.target?.number) || 'N/A',
            country: refill.country || (refill.target?.country) || 'N/A',
            carrier: refill.nodeName || (refill.carrier?.name) || 'Global eSIM',
            confirmationNumber: refill.confirmationNumber || 'PENDING'
        }));

        return res.json({ 
            success: true, 
            refills: formattedRefills 
        });

    } catch (error) {
        console.error("Admin Fetch Error:", error);
        return res.status(500).json({ 
            success: false, 
            message: "Failed to fetch eSIM refill records" 
        });
    }
}

async function handleAdminEsimUpdate(req, res) {
    // 1. Double-check body exists (Vercel/Express parses JSON automatically)
    if (!req.body || Object.keys(req.body).length === 0) {
        console.error("Empty request body - expected JSON");
        return res.status(400).json({ 
            success: false, 
            message: "Data parsing failed. Ensure Content-Type is application/json." 
        });
    }

    const OrderModel = mongoose.models.Order || mongoose.model('Order');
    
    // 2. Consistent variable extraction from req.body
    // Note: receiptUrl now comes directly from the frontend JSON, not req.file
    const tid = req.body.tid || req.body.paymentReference;
    const confirmationNumber = req.body.confirmationNumber;
    const adminNote = req.body.adminNote || '';
    const receiptUrl = req.body.receiptUrl || null; 

    if (!tid) {
        return res.status(400).json({ success: false, message: "Transaction ID (tid) is required." });
    }

    try {
        const updateData = {
            status: 'completed',
            confirmationNumber: confirmationNumber,
            adminNote: adminNote,
            updatedAt: new Date()
        };

        // If the frontend successfully uploaded to Cloudinary, we save the link
        if (receiptUrl) {
            updateData.receiptUrl = receiptUrl; 
        }

        // Search by paymentReference as per your schema
        const updatedOrder = await OrderModel.findOneAndUpdate(
            { paymentReference: tid }, 
            { $set: updateData },
            { new: true } 
        );

        if (!updatedOrder) {
            return res.status(404).json({ success: false, message: "Order not found in Database." });
        }

        // 3. Decoupled Email Block
        try {
            if (typeof sendDeliveryEmail === 'function') {
                await sendDeliveryEmail(updatedOrder.userEmail, {
                    productType: updatedOrder.productType,
                    nodeName: updatedOrder.nodeName || updatedOrder.carrier?.name || "eSIM Carrier",
                    targetNumber: updatedOrder.targetNumber || 'N/A',
                    country: updatedOrder.country || 'N/A',
                    amount: updatedOrder.amount, 
                    confirmationNumber: confirmationNumber,
                    receiptUrl: receiptUrl,
                    instructions: "Your eSIM refill is now active."
                });
            }
        } catch (emailErr) {
            console.error("Email notification failed:", emailErr.message);
            // Non-blocking: order is already saved
        }

        return res.json({ 
            success: true, 
            message: "Order marked as completed.",
            data: updatedOrder 
        });

    } catch (error) {
        console.error("CRITICAL ADMIN ERROR:", error.message);
        return res.status(500).json({ 
            success: false, 
            message: "Database update failed", 
            error: error.message 
        });
    }
}

async function handleAdminEsimActivationUpdate(req, res) {
    // 1. Added receiptUrl to the request body
    const { tid, status, confirmationNumber, receiptUrl } = req.body;

    if (!tid || !status) {
        return res.status(400).json({ success: false, message: "Missing Transaction ID or Status" });
    }

    try {
        const updatedOrder = await Order.findOneAndUpdate(
            { paymentReference: tid, productType: 'eSIM_Activation' }, 
            { 
                $set: { 
                    status: status, 
                    confirmationNumber: confirmationNumber || null,
                    // 2. Save receipt URL to Order metadata or top level
                    "metadata.receiptUrl": receiptUrl || null, 
                    updatedAt: new Date() 
                } 
            },
           { returnDocument: 'after' }
        );

        if (!updatedOrder) {
            return res.status(404).json({ success: false, message: "Activation record not found in Orders" });
        }

        await EsimActivation.findOneAndUpdate(
            { paymentReference: tid },
            { 
                $set: { 
                    status: status, 
                    esimProfileId: confirmationNumber || null,
                    receiptUrl: receiptUrl || null, // 3. Sync to specialized activation record
                    updatedAt: new Date() 
                } 
            }
        );

        const isFinished = status.toLowerCase() === 'completed' || status.toLowerCase() === 'successful';        
        
        if (isFinished) {
            try {
                await sendDeliveryEmail(updatedOrder.userEmail, {
                    productType: "eSIM_Activation", 
                    nodeName: updatedOrder.nodeName || "Global eSIM",
                    planName: updatedOrder.planName || "Standard Plan",
                    amount: updatedOrder.amount,        
                    targetNumber: updatedOrder.targetNumber || "eSIM Device",
                    confirmationNumber: confirmationNumber || updatedOrder.confirmationNumber,
                    receiptUrl: receiptUrl || null, // 4. Pass receipt to email template
                    metadata: {
                        ...updatedOrder.metadata,
                        activationEmail: updatedOrder.metadata?.activationEmail || updatedOrder.userEmail 
                    },
                    firstName: updatedOrder.metadata?.firstName,
                    lastName: updatedOrder.metadata?.lastName,
                    instructions: "Your eSIM activation is complete. You can download your receipt from your dashboard."
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
    const { amount, useBonus, details } = req.body;
    const userId = req.user._id;
    const userEmail = req.user.email;

    if (!amount || !details.carrier || !details.deviceName) {
        return res.status(400).json({ success: false, message: "Missing required activation details" });
    }

    try {
        const user = await User.findById(userId);
        const totalAmount = parseInt(amount);

        // 1. Calculate Balance Deduction (Main vs Bonus)
        let mainToDeduct = totalAmount;
        let bonusToDeduct = 0;

        if (useBonus && user.bonusBalance > 0) {
            bonusToDeduct = Math.min(user.bonusBalance, totalAmount);
            mainToDeduct = totalAmount - bonusToDeduct;
        }

        if (user.balance < mainToDeduct) {
            return res.status(400).json({ success: false, message: "Insufficient wallet balance" });
        }

        const txRef = `ACT-WAL-${Date.now()}`;

        // 2. Create specialized eSIM Activation record
        const activation = new EsimActivation({
            userId,
            userEmail,
            customerDetails: {
                firstName: details.firstName,
                lastName: details.lastName,
                address: details.address,
                zipCode: details.zip,
                email: details.email // Activation specific email
            },
            carrier: { name: details.carrier },
            activationType: details.activationType || 'Standard',
            deviceName: details.deviceName,
            amount: totalAmount,
            receiptUrl: details.receiptUrl || null,
            mainBalanceUsed: mainToDeduct,
            bonusBalanceUsed: bonusToDeduct,
            paymentReference: txRef,
            status: 'pending'
        });

        // 3. Create General Order record for the main Dashboard
        const order = new Order({
            userId,
            userEmail,
            productType: 'eSIM_Activation',
            nodeName: details.carrier,
            targetNumber: details.deviceName,
            planName: `₦${totalAmount.toLocaleString()} Plan`,
            amount: totalAmount,
            mainBalanceUsed: mainToDeduct,
            bonusBalanceUsed: bonusToDeduct,
            status: 'pending',
            paymentReference: txRef,
            metadata: { ...details }
        });

        // 4. Atomic Update: Deduct balances and save records
        user.balance -= mainToDeduct;
        user.bonusBalance -= bonusToDeduct;

        await Promise.all([
            user.save(),
            activation.save(),
            order.save()
        ]);

        res.json({ 
            success: true, 
            message: "Activation order received", 
            order: activation 
        });

    } catch (error) {
        console.error("eSIM Activation Error:", error);
        res.status(500).json({ success: false, message: "Internal Server Error" });
    }
}

async function handleGetEsimActivations(req, res) { 
    try {
        const activations = await Order.find({ productType: 'eSIM_Activation' })
            .sort({ createdAt: -1 })
            .limit(100);

        const formattedActivations = activations.map(order => {
            const details = order.metadata || {};

            return {
                paymentReference: order.paymentReference,
                productType: 'eSIM_Activation', 
                createdAt: order.createdAt,
                userEmail: order.userEmail, 
                email: details.email || order.userEmail,
                fullName: `${details.firstName || ''} ${details.lastName || ''}`.trim() || 'N/A',
                amount: order.amount,
                status: order.status,
                carrierName: order.nodeName || "Global eSIM", // Map nodeName to carrier
                deviceName: order.targetNumber || "eSIM Device", // Map targetNumber to device
                activationType: details.activationType || 'Standard', // Pull from metadata
                planName: order.planName,
                confirmationNumber: order.confirmationNumber || 'PENDING',
                address: details.address || 'N/A',
                zipCode: details.zip || 'N/A'
            };
        });

        return res.json({ success: true, orders: formattedActivations });
    } catch (error) {
        return res.status(500).json({ success: false, message: "Failed to fetch records" });
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

// Updated: Complete RDP Order (Aligned with eSIM Refill Pattern)
async function handleCompleteRDPOrder(req, res) {
    // 1. Extract data from req.body (receiptUrl now comes as a string from frontend)
    const { 
        tid, 
        status, 
        confirmationNumber, 
        ipAddress, 
        port, 
        rdpUsername, 
        rdpPassword,
        receiptUrl 
    } = req.body;

    // Basic validation
    if (!tid) {
        return res.status(400).json({ success: false, message: "Transaction ID (tid) is required." });
    }

    try {
        // 2. Update the order in MongoDB
        const order = await Order.findOneAndUpdate(
            { paymentReference: tid },
            { 
                $set: {
                    status: status || 'completed',
                    confirmationNumber: confirmationNumber, 
                    ipAddress: ipAddress,
                    port: port || '3389',
                    rdpUsername: rdpUsername,
                    rdpPassword: rdpPassword,
                    receiptUrl: receiptUrl || '', // Store the URL directly from the body
                    deliveredAt: new Date(),
                    updatedAt: new Date()
                }
            },
            { new: true } 
        );

        if (!order) {
            return res.status(404).json({ success: false, message: "Order not found" });
        }

        // 3. Trigger Delivery Email (Non-blocking)
        try {
            if (typeof sendDeliveryEmail === 'function') {
                await sendDeliveryEmail(order.userEmail, { 
                    productType: 'RDP', 
                    fullName: order.fullName || 'Customer',
                    confirmationNumber: confirmationNumber,         
                    os: order.os || 'Windows Server',
                    ram: order.ram || 'N/A',
                    cpu: order.cpu || 'N/A',
                    storage: order.storage || 'N/A',        
                    net: order.net || '1Gbps',
                    ipAddress: ipAddress || order.ipAddress,
                    port: port || order.port || '3389',
                    rdpUsername: rdpUsername || order.rdpUsername,
                    rdpPassword: rdpPassword || order.rdpPassword,
                    receiptUrl: receiptUrl || order.receiptUrl, 
                    planName: order.planName || "RDP Service",
                    amount: order.amount
                });
            }
        } catch (mailError) {
            console.error("Email failed but database updated:", mailError.message);
        }

        return res.status(200).json({ 
            success: true, 
            message: "RDP Provisioned successfully", 
            order 
        });

    } catch (error) {
        console.error("RDP Fulfillment Error:", error.message);
        return res.status(500).json({ 
            success: false, 
            message: "Internal Server Error",
            error: error.message 
        });
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
            const meta = order.metadata || {};
            
            return {
                paymentReference: order.paymentReference,
                productType: 'RDP',
                createdAt: order.createdAt,
                userEmail: order.userEmail,
                fullName: order.fullName || meta.fullName || 'User',
                nodeName: order.nodeName || 'USA Tier 1',
                planName: order.planName || 'RDP Server',
                
                // Hardware Specs - Pulling from root or metadata
                cpu: order.cpu || meta.cpu || 'N/A', 
                ram: order.ram || meta.ram || 'N/A',
                storage: order.storage || meta.storage || 'N/A',
                net: order.net || meta.net || 'N/A',
                os: order.os || meta.osChoice || 'Windows',

                receiptUrl: order.receiptUrl || '',
                ipAddress: order.ipAddress || '',
                port: order.port || '',
                rdpUsername: order.rdpUsername || '',
                rdpPassword: order.rdpPassword || '',
                
                metadata: {
                    extraCPU: meta.extraCPU || order.extraCPU || 0,
                    extraStorage: meta.extraStorage || order.extraStorage || 0
                },
                amount: order.amount, 
                status: order.status || 'pending',
                confirmationNumber: order.confirmationNumber || ''
            };
        });

        return res.json({ success: true, orders: formattedRequests });
    } catch (error) {
        console.error("❌ RDP Fetch Error:", error);
        return res.status(500).json({ success: false, message: "Failed to fetch" });
    }
}

/**
 * 1. PURCHASE / ALLOCATE NUMBER FROM SMSBOWER
 */
async function handlePurchaseNumber(req, res) {
    try {
        await connectDB();
        const { planAmount, metadata } = req.body;
        const userId = req.user._id;

        const serviceCode = metadata?.serviceCode || metadata?.serviceName || 'ot';
        const countryId = metadata?.countryCode || metadata?.countryId || 0;

        // 1. Verify user wallet balance
        const user = await User.findById(userId);
        if (!user || user.balance < planAmount) {
            return res.status(400).json({ success: false, message: "Insufficient wallet balance." });
        }

        // 2. Call SMSBower Number Allocation API (SMS-Activate format: action=getNumber)
        const response = await smsBowerClient.get('', {
            params: {
                action: 'getNumber',
                service: serviceCode,
                country: countryId
            }
        });

        const respText = response.data; // e.g., "ACCESS_NUMBER:1:2347012345678:123456" or "NO_NUMBERS"
        
        if (typeof respText === 'string' && respText.startsWith('ACCESS_NUMBER')) {
            const parts = respText.split(':');
            const vendorOrderId = parts[1];
            const allocatedNumber = parts[2];

            // 3. Deduct user balance & save local order record
            user.balance -= planAmount;
            await user.save();

            const newOrder = await SmsNumber.create({
                userId: userId,
                userEmail: user.email,
                phoneNumber: allocatedNumber,
                vendorOrderId: String(vendorOrderId),
                countryId: String(countryId),
                serviceName: serviceCode,
                status: 'pending',
                amount: planAmount,
                expiresAt: new Date(Date.now() + 15 * 60 * 1000)
            });

            return res.json({
                success: true,
                order: newOrder
            });
        } else {
            return res.status(400).json({
                success: false,
                message: respText || "No numbers available from SMSBower right now."
            });
        }

    } catch (err) {
        console.error("SMSBower Purchase Error:", err.message);
        return res.status(500).json({ success: false, message: "Server error processing purchase." });
    }
}
/**
 * 2. FETCH SERVICES (Strictly utilizing SMSBower API response data)
 */
async function handleGetServicesAndPrices(req, res) {
    try {
        if (!process.env.SMSBOWER_API_KEY) {
            console.error("SMSBOWER_API_KEY is missing in your environment configuration.");
            return res.status(500).json({ success: false, message: "Vendor configuration error." });
        }

        // Call the official SMSBower services endpoint
        const response = await smsBowerClient.get('', {
            params: { 
                action: 'services', 
                api_key: process.env.SMSBOWER_API_KEY 
            }
        });

        const rawData = response.data;

        if (typeof rawData === 'string') {
            console.error("SMSBower returned string error:", rawData);
            return res.status(400).json({ success: false, message: `Vendor error: ${rawData}` });
        }

        // Extract the service items array from SMSBower's response
        const serviceItems = rawData.services || rawData.data || (Array.isArray(rawData) ? rawData : []);

        let servicesList = serviceItems.map(item => {
            const code = (item.code || item.id || '').toLowerCase();
            const name = item.name || code.toUpperCase();
            
            return {
                code: code,
                name: name,
                image: item.image || item.icon || `https://smsbower.app/img/services/${code}.svg`,
                countries: {} // Populated dynamically when user expands the accordion
            };
        });

        return res.json({ 
            success: true, 
            services: servicesList 
        });

    } catch (err) {
        console.error("Failed to fetch SMSBower services:", err.response?.data || err.message);
        return res.status(500).json({ 
            success: false, 
            message: "Failed to fetch services catalog from vendor.",
            error: err.message 
        });
    }
}

async function handleGetCountries(req, res) {
    try {
        const serviceCode = req.query.service || req.params.service;
        const targetRank = req.query.rank ? String(req.query.rank).toLowerCase() : null;

        if (!serviceCode) {
            return res.status(400).json({ success: false, message: "Service code is required." });
        }

        const response = await smsBowerClient.get('', {
            params: { 
                action: 'getPrices',
                service: String(serviceCode).toLowerCase(),
            }
        });

        const rawData = response.data;
        const markupPercent = 0; 
        const multiplier = 1 + (markupPercent / 100);
        const exchangeRateToNgn = 1650; 

        let formattedCountries = [];

        if (rawData && typeof rawData === 'object') {
            // Traverse country-first structure: { countryId: { serviceCode: { cost, count, ... } } }
            Object.keys(rawData).forEach(countryId => {
                const countryServices = rawData[countryId];
                if (!countryServices || typeof countryServices !== 'object') return;

                // Find pricing for our specific service code inside this country
                const serviceData = countryServices[serviceCode] || countryServices[String(serviceCode).toLowerCase()];
                if (!serviceData) return;

                // serviceData can be an object containing tiers or a direct pricing object
                const tierKeys = Object.keys(serviceData);
                if (tierKeys.length === 0) return;

                tierKeys.forEach(tierKey => {
                    const tierItem = serviceData[tierKey];
                    
                    if (tierItem && typeof tierItem === 'object' && (tierItem.cost || tierItem.price || tierItem.count)) {
                        let currentRank = String(tierItem.rank || tierKey).toLowerCase();

                        const isSilverOrBronze = currentRank.includes('silver') || currentRank.includes('bronze') || tierKey === 'silver' || tierKey === 'bronze' || !tierItem.rank;

                        if (isSilverOrBronze) {
                            if (!targetRank || currentRank.includes(targetRank)) {
                                const rawCost = Number(tierItem.cost || tierItem.price || 0);
                                const finalAmount = Number((rawCost * exchangeRateToNgn * multiplier).toFixed(2));

                                formattedCountries.push({
                                    countryId: countryId,
                                    countryName: tierItem.countryName || tierItem.name || `Country ${countryId}`,
                                    stock: tierItem.count || tierItem.stock || 'In Stock',
                                    rank: currentRank.includes('silver') ? 'Silver' : (currentRank.includes('bronze') ? 'Bronze' : 'Standard'),
                                    price: {
                                        amount: finalAmount > 0 ? finalAmount : 1650, 
                                        currency: 'NGN',
                                        symbol: '₦'
                                    }
                                });
                            }
                        }
                    }
                });
            });
        }

        return res.json({ success: true, countries: formattedCountries });
    } catch (err) {
        console.error("Failed to fetch SMSBower countries:", err.message);
        return res.status(500).json({ success: false, message: "Failed to fetch country catalog." });
    }
}


/**
 * 3. CHECK ORDER STATUS / SMS CODE POLLING
 */
async function handleOrderDetails(req, res) {
    const { id } = req.query; // Local DB Order ID

    try {
        await connectDB();
        const order = await SmsNumber.findById(id);
        if (!order) return res.status(404).json({ success: false, message: "Order not found." });

        if (order.status === 'completed' || order.smsCode) {
            return res.json({ success: true, order });
        }

        // Poll SMSBower for status (SMS-Activate format: action=getStatus&id=vendorOrderId)
        if (order.vendorOrderId) {
            const response = await smsBowerClient.get('', {
                params: {
                    action: 'getStatus',
                    id: order.vendorOrderId
                }
            });

            const respText = response.data; // e.g., "STATUS_OK:1234" or "STATUS_WAIT_CODE"

            if (typeof respText === 'string' && respText.startsWith('STATUS_OK')) {
                const code = respText.split(':')[1];
                order.smsCode = code;
                order.fullMessage = `Verification Code: ${code}`;
                order.status = 'completed';
                await order.save();
            }
        }

        return res.json({ success: true, order });
    } catch (err) {
        console.error("SMSBower Polling Error:", err.message);
        return res.status(500).json({ success: false, message: "Failed to read order update." });
    }
}

/**
 * 5. WEBHOOK HANDLER (Kept for external Android Gateway fallback)
 */
async function handleSmsReceive(req, res) {
    const { message, deviceId } = req.body;
    const signingSecret = req.headers['x-signing-secret'];

    if (signingSecret !== "c5d55ea9-1dc3-4569-81d8-9a49114c2155") {
        return res.status(401).send("Unauthorized");
    }

    try {
        await connectDB();
        const otpCode = message.match(/\d{4,6}/)?.[0];

        if (otpCode) {
            const updatedRecord = await SmsNumber.findOneAndUpdate(
                { deviceId: deviceId, status: 'pending' },
                { 
                    smsCode: otpCode, 
                    fullMessage: message, 
                    status: 'completed' 
                },
                { sort: { createdAt: -1 }, new: true }
            );

            if (updatedRecord) {
                console.log(`OTP ${otpCode} assigned to user: ${updatedRecord.userEmail}`);
            } else {
                console.warn(`SMS received but no pending order found for device: ${deviceId}`);
            }
        }

        return res.status(200).send("OK");
    } catch (err) {
        console.error("Webhook Error:", err);
        return res.status(500).send("Error");
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
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
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
async function handleGetOrderDetails(req, res) {
    try {
        const orderId = req.query.id; // Get ID from URL query ?id=...
        if (!orderId) return res.status(400).json({ success: false, message: "Order ID required" });

        const order = await Order.findById(orderId);
        if (!order) return res.status(404).json({ success: false, message: "Order not found" });

        res.json({ success: true, order });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
}

// Add this function logic
async function handleSmsWebhook(req, res) {
    try {
        const { message, sender, deviceId } = req.body;
        console.log(`📩 New SMS from ${sender}: ${message}`);

        const order = await Order.findOne({ 
            targetNumber: sender, // or the number receiving the text
            productType: 'SmsNumber',
            status: 'successful' // The financial status was successful
        }).sort({ createdAt: -1 });

        if (!order) {
            console.log("No matching pending order found for this sender.");
            return res.status(200).json({ success: true }); // Always return 200 to TextBee
        }

        const codeMatch = message.match(/\b\d{4,6}\b/);
        const extractedCode = codeMatch ? codeMatch[0] : null;

        if (extractedCode) {
            order.smsCode = extractedCode;
            order.fullMessage = message;
            await order.save();
            await SmsNumber.findOneAndUpdate(
                { phoneNumber: order.targetNumber, status: 'pending' },
                { smsCode: extractedCode, fullMessage: message, status: 'completed' }
            );

            console.log(`✅ Code ${extractedCode} saved to Order ${order._id}`);
        }

        return res.status(200).json({ success: true });
    } catch (err) {
        console.error("Webhook Error:", err.message);
        return res.status(200).json({ success: false }); // Still return 200 so TextBee doesn't retry infinitely
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

