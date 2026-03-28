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
    imageUrl: { type: String },
    activationCode: { type: String },
    instructions: { type: String },
    // Merged Tier: Each plan contains its own IP count and Price
    plans: [{
        ip_count: { type: Number, required: true },
        price: { type: Number, required: true }
    }],
    createdAt: { type: Date, default: Date.now }
});

const Proxy = mongoose.models.Proxy || mongoose.model('Proxy', ProxySchema);

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
        const User = mongoose.models.User || mongoose.model('User', new mongoose.Schema({}, { strict: false }), 'users');
        const Order = mongoose.models.Order || mongoose.model('Order', new mongoose.Schema({}, { strict: false }), 'orders');

        const totalUsers = await User.countDocuments();
        
        const now = new Date();
        const startOfDay = new Date().setHours(0,0,0,0);
        const startOfWeek = new Date().setDate(now.getDate() - 7);
        const startOfMonth = new Date(now.getFullYear(), now.getMonth(), 1);

        const orders = await Order.find({ status: 'successful' });

        // Pull rate from .env
        const RATE = parseFloat(process.env.USD_TO_NGN_RATE) || 1650; 

        let stats = {
            totalRevenue: 0,
            daily: 0,
            weekly: 0,
            monthly: 0
        };

        orders.forEach(order => {
            const amt = parseFloat(order.amount || 0);
            const date = new Date(order.createdAt || order.timestamp);

            stats.totalRevenue += amt;
            if (date >= startOfDay) stats.daily += amt;
            if (date >= startOfWeek) stats.weekly += amt;
            if (date >= startOfMonth) stats.monthly += amt;
        });

        // Send both currencies to frontend
        return res.json({ 
            success: true, 
            totalUsers,
            rateUsed: RATE, // Optional: useful for debugging
            usd: stats,
            ngn: {
                totalRevenue: stats.totalRevenue * RATE,
                daily: stats.daily * RATE,
                weekly: stats.weekly * RATE,
                monthly: stats.monthly * RATE
            }
        });
    } catch (err) {
        console.error("Stats Error:", err);
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
    const { vpnId, planIndex } = req.body;
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    try {
        // We still verify the token to ensure the user is logged in
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

        // 4. Update Inventory Only
        // We decrement the stock because the user "claimed" a spot
        vpn.stock -= 1;
        await vpn.save();

        // 5. Return Credentials
        return res.json({ 
            success: true, 
            message: "Access granted successfully!",
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
    const { vpnId, planIndex } = req.body;
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    // --- CONVERSION RATE CONFIG ---
    // Change this value whenever you want to update your dollar rate
    const USD_TO_NGN_RATE = 1650; 
    // ------------------------------

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await User.findById(decoded.id);
        const vpn = await VPN.findById(vpnId);

        if (!vpn || !vpn.plans[planIndex]) {
            return res.status(404).json({ success: false, message: "Plan not found" });
        }

        const selectedPlan = vpn.plans[planIndex];
        
        // CALCULATE NAIRA AMOUNT
        // We multiply the USD price by our rate
        const amountInNGN = Math.round(selectedPlan.price * USD_TO_NGN_RATE);

        const tx_ref = `SMS-VPN-${Date.now()}-${decoded.id.slice(-4)}`;

        const response = await fetch("https://api.flutterwave.com/v3/payments", {
            method: "POST",
            headers: {
                Authorization: `Bearer ${process.env.FLW_SECRET_KEY}`,
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                tx_ref: tx_ref,
                amount: amountInNGN, // This is now in Naira
                currency: "NGN",     // Changed currency to NGN
                redirect_url: "https://smsglobe.vercel.app/smsuser/user_vpn.html",
                customer: {
                    email: user.email,
                    name: user.fullName,
                },
                meta: {
                    vpnId: vpnId, // Storing this so verify-payment knows what was bought
                    planIndex: planIndex
                },
                customizations: {
                    title: "SMSGlobe VPN",
                    // We show the user the USD price in the description so they aren't confused
                    description: `Access for ${vpn.name} ($${selectedPlan.price} USD @ ₦${USD_TO_NGN_RATE}/$)`,
                    logo: "https://imgur.com/8YeZgfx.png"
                },
            }),
        });

        const data = await response.json();
        if (data.status === "success") {
            return res.json({ success: true, link: data.data.link });
        } else {
            return res.status(500).json({ success: false, message: "Gateway Error" });
        }
    } catch (err) {
        return res.status(401).json({ success: false, message: "Unauthorized" });
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
            const purchasedVpnId = data.data.meta.vpnId;
            const userEmail = data.data.customer.email; // Get email from Flutterwave response
            
            const vpn = await VPN.findById(purchasedVpnId).select('+password');

            if (vpn && vpn.stock > 0) {
                vpn.stock -= 1;
                await vpn.save();
                
                const credentials = {
                    username: vpn.username,
                    password: vpn.password,
                    deviceLimit: vpn.deviceLimit, 
                    instructions: vpn.instructions || "Download the client and use these credentials."
                };

                // --- SEND EMAIL NOTIFICATION ---
                try {
                    await sendVPNEmail(userEmail, credentials);
                } catch (mailErr) {
                    console.error("Email Delivery Failed:", mailErr);
                    // We don't block the response if email fails, 
                    // user still gets credentials on their screen.
                }

                return res.json({ 
                    success: true, 
                    credentials: credentials 
                });
            } else {
                return res.status(400).json({ success: false, message: "Node sold out during transaction." });
            }
        }
        res.status(400).json({ success: false, message: "Transaction not confirmed." });
    } catch (err) {
        console.error("Verification Error:", err);
        res.status(500).json({ success: false, message: "Server verification error." });
    }
}

const sendVPNEmail = async (userEmail, credentials) => {
    const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASS
        }
    });

    // Ensure we have a fallback if deviceLimit is missing
    const displayLimit = credentials.deviceLimit || 1;

    const htmlContent = `
    <!DOCTYPE html>
    <html>
    <head>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            @media screen and (max-width: 480px) {
                .mobile-full { width: 100% !important; display: block !important; text-align: left !important; }
                .header-padding { padding: 20px !important; }
            }
        </style>
    </head>
    <body style="margin: 0; padding: 0; background-color: #f4f7ff;">
        <table border="0" cellpadding="0" cellspacing="0" width="100%">
            <tr>
                <td align="center" style="padding: 20px 0;">
                    <div style="font-family: 'Inter', Helvetica, sans-serif; max-width: 600px; margin: auto; border: 1px solid #e2e8f0; border-radius: 16px; overflow: hidden; background-color: #ffffff; box-shadow: 0 4px 12px rgba(0,0,0,0.05);">
                        
                        <div style="background-color: #ffffff; padding: 20px; text-align: center; border-bottom: 1px solid #f0f0f0;">
                            <img src="https://imgur.com/8YeZgfx.png" alt="SMSGlobe" style="height: 24px; width: auto; display: block; margin: 0 auto;">
                        </div>

                        <div class="header-padding" style="background-color: #0F54C6; color: white; padding: 35px 24px; text-align: center;">
                            <h2 style="margin: 0; font-size: 22px; letter-spacing: -0.5px;">Node Activated! ✅</h2>
                            <p style="opacity: 0.8; font-size: 13px; margin-top: 8px;">Your Premium VPN Access is officially ready.</p>
                        </div>

                        <div style="padding: 24px; color: #344054; text-align: left;">
                            <p style="font-size: 14px; line-height: 1.5; margin-bottom: 24px;">
                                Hello, <br><br>
                                Thank you for choosing <strong>SMSGlobe</strong>. Your payment was confirmed and your secure connection node is now provisioned.
                            </p>
                            
                            <div style="background: #F0F5FE; padding: 20px; border-radius: 12px; border: 1px solid #D1E0FF; margin-bottom: 24px;">
                                <p style="margin: 0 0 10px 0; font-size: 10px; color: #0F54C6; font-weight: 800; text-transform: uppercase; letter-spacing: 1px;">Instructions</p>
                                <p style="font-size: 13px; margin: 0 0 20px 0; line-height: 1.6; color: #101828;">${credentials.instructions}</p>
                                
                                <table border="0" cellpadding="0" cellspacing="0" width="100%" style="border-top: 1px solid #D1E0FF; padding-top: 15px;">
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
                                            <span style="font-size: 9px; color: #667085; text-transform: uppercase; font-weight: bold;">Device Limit</span><br>
                                            <strong style="font-size: 13px; color: #101828;">${displayLimit} Device(s)</strong>
                                        </td>
                                    </tr>
                                </table>
                            </div>

                            <table border="0" cellpadding="0" cellspacing="0" width="100%" style="background: #FFF9F2; border-radius: 8px; border: 1px solid #FFEACC;">
                                <tr>
                                    <td style="padding: 12px; font-size: 11px; color: #B54708; line-height: 1.4;">
                                        <strong>Security Notice:</strong> Never share these keys. SMSGlobe support will never ask for your password. Access is limited to <strong>${displayLimit} device(s)</strong> at a time.
                                    </td>
                                </tr>
                            </table>

                            <div style="text-align: center; margin-top: 30px;">
                                <a href="https://smsglobe.com/login" style="background-color: #0F54C6; color: #ffffff; padding: 12px 24px; text-decoration: none; font-size: 13px; font-weight: bold; border-radius: 8px; display: inline-block;">Access Dashboard</a>
                            </div>
                        </div>

                        <div style="background: #F9FAFB; padding: 20px; text-align: center; border-top: 1px solid #EAECF0;">
                            <p style="font-size: 11px; color: #667085; margin: 0;">&copy; 2026 <strong>SMSGlobe</strong>. All rights reserved.</p>
                            <p style="font-size: 10px; color: #98A2B3; margin-top: 5px;">Reliable Virtual Communications & Global Connectivity</p>
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
        subject: "🔑 Your VPN Access Credentials - SMSGlobe",
        html: htmlContent
    });
};

// --- PROXY HANDLERS ---

async function handleGetProxies(req, res) {
    try {
        const proxies = await Proxy.find({}).sort({ createdAt: -1 });
        return res.json({ success: true, proxies });
    } catch (err) {
        return res.status(500).json({ success: false, message: "Fetch failed" });
    }
}

async function handleAddProxy(req, res) {
    try {
        const data = req.body;

        // Clean and parse the merged Pricing/IP tiers
        if (data.plans && Array.isArray(data.plans)) {
            data.plans = data.plans.map(p => ({
                ip_count: parseInt(p.ip_count) || 0,
                price: parseFloat(p.price) || 0
            }));
        }

        const newProxy = new Proxy(data);
        await newProxy.save();
        
        return res.json({ success: true, message: "Proxy Package Deployed Successfully" });
    } catch (err) {
        console.error("Add Proxy Error:", err);
        return res.status(500).json({ success: false, message: "Deployment failed" });
    }
}

async function handleUpdateProxy(req, res) {
    try {
        const { proxyId, ...updateData } = req.body;

        if (updateData.plans && Array.isArray(updateData.plans)) {
            updateData.plans = updateData.plans.map(p => ({
                ip_count: parseInt(p.ip_count) || 0,
                price: parseFloat(p.price) || 0
            }));
        }

        const updated = await Proxy.findByIdAndUpdate(proxyId, updateData, { new: true });
        
        if (!updated) return res.status(404).json({ success: false, message: "Proxy not found" });

        return res.json({ success: true, message: "Proxy Package Updated" });
    } catch (err) {
        return res.status(500).json({ success: false, message: "Update failed" });
    }
}

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
// --- 8. STARTUP ---
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

if (process.env.NODE_ENV !== 'production') {
    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () => console.log(`Dev Server: http://localhost:${PORT}`));
}

module.exports = app;