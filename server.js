/* server.js */
require("dotenv").config();

const express = require("express");
const cors = require("cors");
const multer = require("multer");
const mongoose = require("mongoose");
const Razorpay = require("razorpay");
const crypto = require("crypto");
const path = require("path");
const url = require("url");

// --- CONFIGURATION ---
const PORT = process.env.PORT || 4000;
const MONGODB_URI = process.env.MONGODB_URI || "mongodb://localhost:27017/whis-app";

// 1. OpenAI Config
const OPENAI_API_KEY = process.env.OPENAI_API_KEY;
const OPENAI_MODEL = process.env.OPENAI_MODEL || "gpt-4o-mini";

// 2. App & Auth Config
const BACKEND_URL = process.env.BACKEND_URL || "http://localhost:4000";
const APP_AUTH_TOKEN = process.env.APP_AUTH_TOKEN;
const WEBSITE_PRICING_URL = process.env.WEBSITE_PRICING_URL;

// 3. Google Auth Config
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const GOOGLE_REDIRECT_URI = process.env.GOOGLE_REDIRECT_URI;

// 4. Payment Gateways
const RAZORPAY_KEY_ID = process.env.RAZORPAY_KEY_ID;
const RAZORPAY_KEY_SECRET = process.env.RAZORPAY_KEY_SECRET;

// PayPal Config
const PAYPAL_CLIENT_ID = process.env.PAYPAL_CLIENT_ID;
const PAYPAL_CLIENT_SECRET = process.env.PAYPAL_CLIENT_SECRET;
const PAYPAL_BASE_URL = process.env.PAYPAL_MODE === 'sandbox' ? "https://api-m.sandbox.paypal.com" : "https://api-m.paypal.com";

const USD_TO_INR = parseFloat(process.env.USD_TO_INR || "90");

// --- COUPON SECRET ---
const COUPON_SECRET = process.env.COUPON_SECRET || "whis-secret-coupon-hash-99";

// --- LIMITS & TRIAL CONFIGURATION ---
const FREE_DAILY_LIMIT = parseInt(process.env.FREE_DAILY_LIMIT || "10", 10);
const FREE_SCREENSHOT_LIMIT = parseInt(process.env.FREE_SCREENSHOT_LIMIT || "3", 10);
const PAID_SCREENSHOT_LIMIT = parseInt(process.env.PAID_SCREENSHOT_LIMIT || "10", 10);
const MAX_TEXT_CHAR_LIMIT = parseInt(process.env.MAX_TEXT_CHAR_LIMIT || "4096", 10);

// --- NEW: ON-DEMAND TRIAL CONFIGURATION ---
const MAX_TRIAL_SESSIONS = parseInt(process.env.MAX_TRIAL_SESSIONS || "3", 10);
const TRIAL_DURATION_MINUTES = 10; 

// --- NEW: PAID MIC LIMIT (MONTHLY) ---
const PAID_MIC_LIMIT_MINUTES = parseInt(process.env.PAID_MIC_LIMIT_MINUTES || "300", 10);
const PAID_MIC_LIMIT_SECONDS = PAID_MIC_LIMIT_MINUTES * 60;

// --- PRICING CONFIGURATION (VALUES IN USD) ---
// Note: 'annual_per_month' is used here to represent the Quarterly per-month rate logic
const PRICING = {
  pro: {
    monthly: parseFloat(process.env.PRO_PER_MONTH || "29"), 
    annual_per_month: parseFloat(process.env.PRO_YEAR_PER_MONTH || "15"),
    discount: parseFloat(process.env.PRO_DISCOUNT || 0)
  },
  pro_plus: {
    monthly: parseFloat(process.env.PROPLUS_PER_MONTH || "49"), 
    annual_per_month: parseFloat(process.env.PROPLUS_YEAR_PER_MONTH || "25"),
    discount: parseFloat(process.env.PROPLUS_DISCOUNT || 0)
  }
};

// --- INITIAL CHECKS ---
console.log("--- 🚀 STARTING SERVER ---");
console.log(`--- 📊 LIMITS: FreeChat=${FREE_DAILY_LIMIT}, MaxTrialSessions=${MAX_TRIAL_SESSIONS} ---`);

if (!OPENAI_API_KEY) console.error("⚠️  MISSING: OPENAI_API_KEY");
if (!RAZORPAY_KEY_ID) console.error("⚠️  MISSING: RAZORPAY_KEY_ID");
if (!PAYPAL_CLIENT_ID) console.error("⚠️  MISSING: PAYPAL_CLIENT_ID");
if (!GOOGLE_CLIENT_ID) console.error("⚠️  MISSING: GOOGLE_CLIENT_ID");

const razorpay = new Razorpay({
  key_id: RAZORPAY_KEY_ID,
  key_secret: RAZORPAY_KEY_SECRET,
});

const upload = multer({ 
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 } 
});

const app = express();
app.set('trust proxy', true);
app.use(cors());
app.use(express.json({ limit: "50mb" }));

// --- 1. MongoDB Connection ---
mongoose
  .connect(MONGODB_URI)
  .then(() => console.log("✅ [DB] Connected to MongoDB"))
  .catch((err) => console.error("❌ [DB] Connection Failed:", err));

// --- 2. SCHEMAS ---

// NEW: Lead Schema
const leadSchema = new mongoose.Schema({
    phone: String,
    email: String,
    source: String, // 'download_gate' or 'coupon_bar'
    ip: String,
    createdAt: { type: Date, default: Date.now }
});
const Lead = mongoose.model("Lead", leadSchema);

const metricSchema = new mongoose.Schema({
  date: { type: String, required: true },
  ip: { type: String, required: true },
  hits: { type: Number, default: 1 },
  referrers: [String],
  os: String,
  isMobile: Boolean,
  stats: {
    chat: { type: Number, default: 0 },
    transcribe: { type: Number, default: 0 },
    payment: { type: Number, default: 0 }
  },
  userId: String,
  lastActive: { type: Date, default: Date.now }
});
metricSchema.index({ date: 1, ip: 1 }, { unique: true });
const Metric = mongoose.model("Metric", metricSchema);

const userSchema = new mongoose.Schema({
  googleId: { type: String, unique: true, required: true },
  email: { type: String, required: true },
  name: String,
  avatarUrl: String,
  phone: String,
  // Session Control
  currentSessionId: { type: String, default: "" },
  subscription: {
    status: { type: String, enum: ["active", "inactive", "past_due"], default: "inactive" },
    tier: { type: String, enum: ["free", "pro", "pro_plus"], default: "free" },
    cycle: { type: String, enum: ["monthly", "annual"], default: "monthly" },
    validUntil: Date,
    isTrial: { type: Boolean, default: false }
  },
  trialUsage: {
    count: { type: Number, default: 0 }
  },
  freeUsage: {
    count: { type: Number, default: 0 },
    lastDate: { type: String }
  },
  screenshotUsage: {
    count: { type: Number, default: 0 },
    lastDate: { type: String }
  },
  micUsage: {
    monthKey: { type: String }, 
    secondsUsed: { type: Number, default: 0 }
  },
  contexts: [
    {
      id: { type: String, required: true }, 
      name: { type: String, required: true }, 
      content: { type: String, required: true },
      isActive: { type: Boolean, default: false },
      updatedAt: { type: Date, default: Date.now }
    }
  ],
  orders: [
    {
      orderId: String, paymentId: String, signature: String, amount: Number,
      currency: String, date: Date, status: String, tier: String, 
      cycle: String, method: String, receipt: String, notes: Object
    }
  ],
  createdAt: { type: Date, default: Date.now },
  lastLogin: Date
});
const User = mongoose.model("User", userSchema);

const conversationSchema = new mongoose.Schema({
  conversationId: { type: String, required: true, unique: true, index: true },
  userId: String,
  messages: [
    {
      role: { type: String, enum: ['user', 'assistant', 'system'] },
      content: mongoose.Schema.Types.Mixed,
      timestamp: { type: Date, default: Date.now }
    }
  ],
  updatedAt: { type: Date, default: Date.now }
});
conversationSchema.index({ updatedAt: 1 }, { expireAfterSeconds: 86400 }); 
const Conversation = mongoose.model("Conversation", conversationSchema);

const freeRequestSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true },
  whatsapp: { type: String, required: true },
  yoe: { type: Number, required: true },
  targetRole: { type: String },
  ip: String,
  timestamp: { type: Date, default: Date.now }
});
const FreeRequest = mongoose.model("free_request", freeRequestSchema);


// --------- 3. SMART TRAFFIC TRACKING MIDDLEWARE ---------
app.use((req, res, next) => {
  const isStatic = req.path.match(/\.(css|js|png|jpg|jpeg|ico|svg|woff|woff2)$/);
  if (!isStatic) console.log(`📥 [REQ] ${req.method} ${req.path}`);
  if (isStatic) return next();

  try {
    const today = new Date().toISOString().slice(0, 10);
    const ip = req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress;
    const ua = req.get('User-Agent') || "";
    const referrerHeader = req.get('Referrer') || req.get('Referer');
    const googleId = req.headers["x-google-id"] || req.body.googleId;

    let os = "Unknown";
    let isMobile = /mobile|android|iphone|ipad|phone/i.test(ua);
    if (/windows/i.test(ua)) os = "Windows";
    else if (/macintosh|mac os/i.test(ua)) os = "Mac";
    else if (/linux/i.test(ua)) os = "Linux";
    else if (/android/i.test(ua)) os = "Android";
    else if (/ios|iphone|ipad/i.test(ua)) os = "iOS";

    let referrerDomain = null;
    if (referrerHeader) {
        try { referrerDomain = new URL(referrerHeader).hostname; } catch (e) {}
    }

    const updates = { 
        $inc: { hits: 1 }, 
        $set: { lastActive: new Date(), os: os, isMobile: isMobile },
        $addToSet: {} 
    };

    if (req.path.includes("/chat-stream")) updates.$inc["stats.chat"] = 1;
    else if (req.path.includes("/transcribe")) updates.$inc["stats.transcribe"] = 1;
    else if (req.path.includes("/payment")) updates.$inc["stats.payment"] = 1;

    if (referrerDomain) updates.$addToSet["referrers"] = referrerDomain;
    else delete updates.$addToSet;
     
    if (googleId) updates.$set["userId"] = googleId;

    Metric.findOneAndUpdate(
      { date: today, ip: ip },
      updates,
      { upsert: true, new: true }
    ).catch(err => console.error("⚠️ Analytics Write Error:", err.message));

  } catch (error) {
    console.error("⚠️ Analytics Logic Error:", error.message);
  }
  next();
});

app.use(express.static(__dirname));

// === ATOMIC USAGE CHECKER ===
async function checkAndIncrementUsage(googleId) {
  const today = new Date().toISOString().slice(0, 10);
  
  let user = await User.findOne({ googleId });
  if (!user) return { allowed: false, error: "User not found" };

  if (user.freeUsage.lastDate !== today) {
      user = await User.findOneAndUpdate(
          { googleId },
          { 
              $set: { 
                  "freeUsage.count": 0, 
                  "freeUsage.lastDate": today,
                  "screenshotUsage.count": 0,
                  "screenshotUsage.lastDate": today 
              } 
          },
          { new: true }
      );
  }

  let isTrialActive = user.subscription.isTrial && user.subscription.validUntil && new Date() < user.subscription.validUntil;
  let isPaidActive = user.subscription.status === 'active';

  if (isPaidActive && user.subscription.validUntil && new Date() > user.subscription.validUntil) {
      console.log(`[Sub] Expired for ${googleId}. Downgrading.`);
      await User.updateOne({ googleId }, { 
          $set: { 
             "subscription.status": "inactive", 
             "subscription.tier": "free",
             "subscription.isTrial": false 
          }
      });
      isPaidActive = false;
      isTrialActive = false;
  }

  if (isPaidActive || isTrialActive) {
      return { allowed: true, tier: user.subscription.tier };
  }

  const result = await User.findOneAndUpdate(
      { 
          googleId: googleId, 
          "freeUsage.count": { $lt: FREE_DAILY_LIMIT } 
      },
      { $inc: { "freeUsage.count": 1 } },
      { new: true }
  );

  if (result) {
      return { allowed: true, tier: 'free', remaining: FREE_DAILY_LIMIT - result.freeUsage.count };
  } else {
      return { allowed: false, error: "Daily limit reached" };
  }
}

// === PAID MIC USAGE HELPERS ===
function getMonthKey(d = new Date()) {
  const year = d.getUTCFullYear();
  const month = String(d.getUTCMonth() + 1).padStart(2, "0");
  return `${year}-${month}`;
}

function isPaidMicEnforced(user) {
  return (
    user &&
    user.subscription &&
    user.subscription.status === "active" &&
    (user.subscription.tier === "pro" || user.subscription.tier === "pro_plus") &&
    !user.subscription.isTrial
  );
}

async function normalizeMicUsageForMonth(user) {
  const monthKey = getMonthKey(new Date());
  if (!user.micUsage) user.micUsage = { monthKey, secondsUsed: 0 };

  if (user.micUsage.monthKey !== monthKey) {
    user.micUsage.monthKey = monthKey;
    user.micUsage.secondsUsed = 0;
    await user.save();
  }
  return user.micUsage;
}

function computeMicRemainingSeconds(user) {
  const used = (user.micUsage && typeof user.micUsage.secondsUsed === "number") ? user.micUsage.secondsUsed : 0;
  return Math.max(0, PAID_MIC_LIMIT_SECONDS - used);
}

async function checkScreenshotLimit(googleId) {
    const today = new Date().toISOString().slice(0, 10);
    const user = await User.findOne({ googleId });
    if (!user) return { allowed: false, error: "User not found" };

    if (!user.screenshotUsage) {
        user.screenshotUsage = { count: 0, lastDate: today };
    }

    if (user.screenshotUsage.lastDate !== today) {
        user.screenshotUsage.count = 0;
        user.screenshotUsage.lastDate = today;
        await user.save();
    }

    const isTrialActive = user.subscription.isTrial && user.subscription.validUntil && new Date() < user.subscription.validUntil;
    const isPaid = (user.subscription.status === 'active' || isTrialActive) && ['pro', 'pro_plus'].includes(user.subscription.tier);
    
    const limit = isPaid ? PAID_SCREENSHOT_LIMIT : FREE_SCREENSHOT_LIMIT;

    const result = await User.findOneAndUpdate(
        { 
            googleId: googleId, 
            "screenshotUsage.count": { $lt: limit } 
        },
        { 
            $inc: { "screenshotUsage.count": 1 },
            $set: { "screenshotUsage.lastDate": today }
        },
        { new: true }
    );

    if (result) {
        return { allowed: true, count: result.screenshotUsage.count, limit };
    } else {
        return { 
            allowed: false, 
            error: isPaid 
                ? `Daily screenshot limit (${limit}) reached.` 
                : `Free daily screenshot limit (${limit}) reached.` 
        };
    }
}

async function getPayPalAccessToken() {
    if (!PAYPAL_CLIENT_ID || !PAYPAL_CLIENT_SECRET) {
        throw new Error("Missing PayPal Credentials");
    }
    const auth = Buffer.from(PAYPAL_CLIENT_ID + ":" + PAYPAL_CLIENT_SECRET).toString("base64");
    const response = await fetch(`${PAYPAL_BASE_URL}/v1/oauth2/token`, {
        method: "POST",
        body: "grant_type=client_credentials",
        headers: {
            Authorization: `Basic ${auth}`,
            "Content-Type": "application/x-www-form-urlencoded",
        },
    });
    if (!response.ok) {
        throw new Error(`PayPal Auth Failed: ${response.statusText}`);
    }
    const data = await response.json();
    return data.access_token;
}

// === COUPON HELPERS ===
function generateCoupon(email) {
    if (!email) return null;
    const hour = new Date().getUTCHours();
    // Simple hash: email + hour + secret (valid for 1 hour)
    const hash = crypto.createHmac('sha256', COUPON_SECRET)
                       .update(`${email.trim().toLowerCase()}-${hour}`)
                       .digest('hex').substring(0, 6).toUpperCase();
    return `WHIS${hash}`;
}

function validateCoupon(code, email) {
    if (!code || !email) return false;
    const validCode = generateCoupon(email);
    // Allow matching the code (In production, could check if hour passed, but this hash rotates hourly)
    return code === validCode;
}

// ================= ROUTES =================

app.get("/ping", (req, res) => res.send("pong"));

app.get("/api/config", (req, res) => {
    res.json({
        pricing: PRICING,
        exchangeRate: USD_TO_INR,
        googleClientId: GOOGLE_CLIENT_ID,
        websitePricingUrl: WEBSITE_PRICING_URL,
        limits: {
            freeChat: FREE_DAILY_LIMIT,
            freeScreenshot: FREE_SCREENSHOT_LIMIT,
            paidScreenshot: PAID_SCREENSHOT_LIMIT,
            maxTextChar: MAX_TEXT_CHAR_LIMIT,
            maxTrialSessions: MAX_TRIAL_SESSIONS
        }
    });
});

// --- NEW COUPON ENDPOINTS ---
app.post("/api/coupon/generate", (req, res) => {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: "Email required" });
    const code = generateCoupon(email);
    res.json({ success: true, code, discount: "20%" });
});

app.post("/api/coupon/validate", (req, res) => {
    const { code, email } = req.body;
    const isValid = validateCoupon(code, email);
    res.json({ valid: isValid, discount: isValid ? 20 : 0 });
});

// --- NEW LEAD ENDPOINT ---
app.post("/api/leads/add", async (req, res) => {
    try {
        const { phone, email, source, googleId } = req.body;
        // Phone or Email is required depending on the source
        if (!phone && !email) return res.status(400).json({ error: "Phone or Email required" });
        
        const ip = req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress;

        // 1. If user is logged in, update their profile
        if (googleId) {
            const updates = {};
            if(phone) updates.phone = phone;
            // Don't overwrite email usually, but can if needed
            await User.findOneAndUpdate({ googleId }, updates);
        }

        // 2. Always save to Lead collection
        const newLead = new Lead({ phone, email, source, ip });
        await newLead.save();

        res.json({ success: true });
    } catch (err) {
        console.error("Lead Error:", err);
        res.status(500).json({ error: "Failed to save lead" });
    }
});

app.post("/api/auth/google", async (req, res) => {
  try {
    const { code, token, tokens } = req.body;
    let idToken = token || (tokens && tokens.id_token);
    let accessToken = tokens && tokens.access_token;

    if (code) {
        if (!GOOGLE_CLIENT_SECRET) {
            return res.status(500).json({ error: "Server misconfiguration" });
        }
        const params = new URLSearchParams();
        params.append("code", code);
        params.append("client_id", GOOGLE_CLIENT_ID);
        params.append("client_secret", GOOGLE_CLIENT_SECRET);
        params.append("redirect_uri", GOOGLE_REDIRECT_URI); 
        params.append("grant_type", "authorization_code");

        const exchangeRes = await fetch("https://oauth2.googleapis.com/token", {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: params
        });

        const exchangeData = await exchangeRes.json();
        if (!exchangeRes.ok) return res.status(401).json({ error: "Failed to exchange code" });
        idToken = exchangeData.id_token;
        accessToken = exchangeData.access_token;
    }

    if (!idToken) return res.status(400).json({ error: "No authentication credential provided" });

    const googleRes = await fetch(`https://oauth2.googleapis.com/tokeninfo?id_token=${idToken}`);
    if (!googleRes.ok) return res.status(401).json({ error: "Invalid Google Token" });

    const payload = await googleRes.json();
    const { sub: googleId, email, name, picture: avatarUrl } = payload;

    const newSessionId = crypto.randomUUID();

    const user = await User.findOneAndUpdate(
      { googleId },
      {
        email, name, avatarUrl, lastLogin: new Date(),
        currentSessionId: newSessionId,
        $setOnInsert: {
          "subscription.status": "inactive", 
          "subscription.tier": "free",
          "trialUsage.count": 0,
          "freeUsage.count": 0, "freeUsage.lastDate": new Date().toISOString().slice(0, 10),
          "screenshotUsage.count": 0, "screenshotUsage.lastDate": new Date().toISOString().slice(0, 10)
        }
      },
      { new: true, upsert: true }
    );
    
    res.json({ success: true, user, tokens: { id_token: idToken, access_token: accessToken } });
  } catch (err) {
    console.error("Auth Error:", err);
    res.status(500).json({ error: "Database or Auth error" });
  }
});

app.post("/api/user/update-phone", async (req, res) => {
  try {
    const { googleId, phone } = req.body;
    if (!googleId || !phone) {
      return res.status(400).json({ error: "Missing required fields" });
    }
    const updatedUser = await User.findOneAndUpdate(
      { googleId: googleId },
      { phone: phone },
      { new: true }
    );
    if (!updatedUser) return res.status(404).json({ error: "User not found" });
    res.json({ success: true, user: updatedUser });
  } catch (err) {
    res.status(500).json({ error: "Internal server error" });
  }
});

app.post("/api/user/trial/start", async (req, res) => {
    try {
        const googleId = req.headers["x-google-id"];
        const { tier } = req.body; 
        
        if (!googleId) return res.status(401).json({ error: "Unauthorized" });
        if (!['pro', 'pro_plus'].includes(tier)) return res.status(400).json({ error: "Invalid tier" });

        const user = await User.findOne({ googleId });
        if (!user) return res.status(404).json({ error: "User not found" });

        if (user.trialUsage && user.trialUsage.count >= MAX_TRIAL_SESSIONS) {
            return res.status(403).json({ error: "Maximum trial sessions reached." });
        }

        const now = new Date();
        const expiry = new Date(now.getTime() + (TRIAL_DURATION_MINUTES * 60 * 1000)); 

        user.subscription.tier = tier;
        user.subscription.validUntil = expiry;
        user.subscription.isTrial = true; 

        if (!user.trialUsage) user.trialUsage = { count: 0 };
        user.trialUsage.count += 1;

        await user.save();
        res.json({ 
            success: true, 
            validUntil: expiry, 
            sessionsUsed: user.trialUsage.count, 
            maxSessions: MAX_TRIAL_SESSIONS 
        });

    } catch (err) {
        res.status(500).json({ error: "Failed to start trial" });
    }
});

app.post("/api/user/trial/end", async (req, res) => {
    try {
        const googleId = req.headers["x-google-id"];
        if (!googleId) return res.status(401).json({ error: "Unauthorized" });

        const user = await User.findOne({ googleId });
        if (!user) return res.status(404).json({ error: "User not found" });

        if (user.subscription.isTrial) {
            user.subscription.validUntil = new Date(); 
            user.subscription.tier = 'free'; 
            user.subscription.isTrial = false;
            
            await user.save();
            return res.json({ success: true });
        }
        return res.json({ success: false, message: "Not in an active trial" });
    } catch (err) {
        res.status(500).json({ error: "Failed to end trial" });
    }
});

app.post("/api/auth/session/rotate", async (req, res) => {
    try {
        const googleId = req.headers["x-google-id"];
        if(!googleId) return res.status(400).json({ error: "Missing ID" });
        const newSessionId = crypto.randomUUID();
        await User.findOneAndUpdate(
            { googleId },
            { currentSessionId: newSessionId }
        );
        res.json({ success: true, newSessionId });
    } catch(err) {
        res.status(500).json({ error: "Rotation failed" });
    }
});

app.get("/api/user/status", async (req, res) => {
  try {
    const googleId = req.headers["x-google-id"];
    const incomingSessionId = req.headers["x-session-id"];
    const isAppRequest = req.headers["x-whis-auth"] === APP_AUTH_TOKEN;

    if (!googleId) return res.status(401).json({ error: "Not authenticated" });

    const user = await User.findOne({ googleId });
    if (!user) return res.json({ active: false, tier: null });

    if (user.currentSessionId && incomingSessionId && user.currentSessionId !== incomingSessionId) {
        return res.json({ sessionInvalid: true });
    }

    const now = new Date();
    if (user.subscription.status === "active" && user.subscription.validUntil && now > user.subscription.validUntil) {
      user.subscription.status = "inactive";
      user.subscription.tier = "free";
      user.subscription.isTrial = false;
      await user.save();
    }
    
    const isRealActive = user.subscription.status === "active";
    const isTrialValid = user.subscription.isTrial && user.subscription.validUntil && now < user.subscription.validUntil;

    let reportedActive = isAppRequest ? (isRealActive || isTrialValid) : isRealActive;

    const micUsageEnforced = isPaidMicEnforced(user);
    if (micUsageEnforced) {
      await normalizeMicUsageForMonth(user);
    } else if (!user.micUsage) {
      user.micUsage = { monthKey: getMonthKey(new Date()), secondsUsed: 0 };
    }
    const micRemainingSeconds = micUsageEnforced ? computeMicRemainingSeconds(user) : null;

    res.json({
      active: reportedActive,
      tier: user.subscription.tier,
      validUntil: user.subscription.validUntil,
      isTrial: !!user.subscription.isTrial, 
      trialUsage: user.trialUsage || { count: 0 },
      maxTrialSessions: MAX_TRIAL_SESSIONS,
      freeUsage: user.freeUsage,
      screenshotUsage: user.screenshotUsage, 
      micUsageEnforced: micUsageEnforced,
      micLimitSeconds: PAID_MIC_LIMIT_SECONDS,
      micRemainingSeconds: micRemainingSeconds,
      micUsage: user.micUsage,
      hasPhone: !!user.phone, // Send flag for strict gating
      orders: user.orders ? user.orders.sort((a,b) => new Date(b.date) - new Date(a.date)) : []
    });
  } catch (err) {
    res.status(500).json({ error: "Failed to check status" });
  }
});

// === MIC ENDPOINTS (Fully Restored) ===

app.get("/api/user/mic/status", async (req, res) => {
  try {
    const googleId = req.headers["x-google-id"];
    const incomingSessionId = req.headers["x-session-id"];
    const isAppRequest = req.headers["x-whis-auth"] === APP_AUTH_TOKEN;

    if (!isAppRequest) return res.status(401).json({ error: "Unauthorized" });
    if (!googleId) return res.status(401).json({ error: "Not authenticated" });

    const user = await User.findOne({ googleId });
    if (!user) return res.status(404).json({ error: "User not found" });

    if (user.currentSessionId && incomingSessionId && user.currentSessionId !== incomingSessionId) {
      return res.json({ sessionInvalid: true });
    }

    const micUsageEnforced = isPaidMicEnforced(user);
    if (micUsageEnforced) {
      await normalizeMicUsageForMonth(user);
    } else if (!user.micUsage) {
      user.micUsage = { monthKey: getMonthKey(new Date()), secondsUsed: 0 };
    }

    const remaining = micUsageEnforced ? computeMicRemainingSeconds(user) : null;

    res.json({
      micUsageEnforced,
      micLimitSeconds: PAID_MIC_LIMIT_SECONDS,
      micRemainingSeconds: remaining,
      micUsage: user.micUsage
    });
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch mic status" });
  }
});

app.post("/api/user/mic/consume", async (req, res) => {
  try {
    const googleId = req.headers["x-google-id"];
    const incomingSessionId = req.headers["x-session-id"];
    const isAppRequest = req.headers["x-whis-auth"] === APP_AUTH_TOKEN;

    if (!isAppRequest) return res.status(401).json({ error: "Unauthorized" });
    if (!googleId) return res.status(401).json({ error: "Not authenticated" });

    const deltaSecondsRaw = req.body && typeof req.body.deltaSeconds === "number" ? req.body.deltaSeconds : 0;
    const deltaSeconds = Math.max(0, Math.min(300, Math.floor(deltaSecondsRaw))); 

    const user = await User.findOne({ googleId });
    if (!user) return res.status(404).json({ error: "User not found" });

    if (user.currentSessionId && incomingSessionId && user.currentSessionId !== incomingSessionId) {
      return res.json({ sessionInvalid: true });
    }

    const micUsageEnforced = isPaidMicEnforced(user);

    if (!micUsageEnforced) {
      if (!user.micUsage) user.micUsage = { monthKey: getMonthKey(new Date()), secondsUsed: 0 };
      return res.json({
        micUsageEnforced: false,
        micLimitSeconds: PAID_MIC_LIMIT_SECONDS,
        micRemainingSeconds: null,
        micUsage: user.micUsage
      });
    }

    await normalizeMicUsageForMonth(user);

    const usedBefore = user.micUsage.secondsUsed || 0;
    const remainingBefore = Math.max(0, PAID_MIC_LIMIT_SECONDS - usedBefore);
    const countedSeconds = Math.min(deltaSeconds, remainingBefore);

    if (countedSeconds > 0) {
      user.micUsage.secondsUsed = usedBefore + countedSeconds;
      await user.save();
    }

    const remainingAfter = computeMicRemainingSeconds(user);

    res.json({
      micUsageEnforced: true,
      micLimitSeconds: PAID_MIC_LIMIT_SECONDS,
      micRemainingSeconds: remainingAfter,
      micUsage: user.micUsage,
      countedSeconds,
      exhausted: remainingAfter <= 0
    });
  } catch (err) {
    res.status(500).json({ error: "Failed to consume mic usage" });
  }
});


// === CONTEXT API ENDPOINTS (Fully Restored) ===

app.get("/api/user/context", async (req, res) => {
  try {
    const googleId = req.headers["x-google-id"];
    if (!googleId) return res.status(401).json({ error: "Unauthorized" });
    const user = await User.findOne({ googleId }, { contexts: 1 });
    if (!user) return res.status(404).json({ error: "User not found" });
    res.json({ contexts: user.contexts || [] });
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch contexts" });
  }
});

app.post("/api/user/context", async (req, res) => {
  try {
    const googleId = req.headers["x-google-id"];
    const { id, name, content, isActive } = req.body;
    
    if (!googleId) return res.status(401).json({ error: "Unauthorized" });
    if (!name || !content) return res.status(400).json({ error: "Name and content required" });

    const user = await User.findOne({ googleId });
    if (!user) return res.status(404).json({ error: "User not found" });

    if (isActive) {
       user.contexts.forEach(c => c.isActive = false);
    }

    const existingIndex = user.contexts.findIndex(c => c.id === id);

    if (existingIndex > -1) {
      user.contexts[existingIndex].name = name;
      user.contexts[existingIndex].content = content;
      if (isActive !== undefined) user.contexts[existingIndex].isActive = isActive;
      user.contexts[existingIndex].updatedAt = new Date();
    } else {
      if (user.contexts.length >= 10) {
        return res.status(400).json({ error: "Context limit reached (Max 10)" });
      }
      user.contexts.push({
        id: id || crypto.randomUUID(),
        name,
        content,
        isActive: !!isActive,
        updatedAt: new Date()
      });
    }

    await user.save();
    res.json({ success: true, contexts: user.contexts });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to save context" });
  }
});

app.post("/api/user/context/toggle", async (req, res) => {
  try {
    const googleId = req.headers["x-google-id"];
    const { id } = req.body;

    const user = await User.findOne({ googleId });
    if (!user) return res.status(404).json({ error: "User not found" });

    user.contexts.forEach(c => c.isActive = false);

    if (id) {
      const target = user.contexts.find(c => c.id === id);
      if (target) target.isActive = true;
    }

    await user.save();
    res.json({ success: true, contexts: user.contexts });
  } catch (err) {
    res.status(500).json({ error: "Failed to toggle context" });
  }
});

app.delete("/api/user/context/:id", async (req, res) => {
  try {
    const googleId = req.headers["x-google-id"];
    const contextId = req.params.id;

    await User.updateOne(
      { googleId },
      { $pull: { contexts: { id: contextId } } }
    );

    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: "Failed to delete" });
  }
});

// === PAYMENT UPDATES (Quarterly + Coupon) ===

app.post("/api/payment/create-order", async (req, res) => {
  try {
    const { googleId, tier, cycle, couponCode } = req.body; 
    const user = await User.findOne({ googleId });
    if (!user) return res.status(404).json({ error: "User not found" });

    let priceInfo;
    let basePrice = 0.00; 
     
    if (tier === "pro") {
        priceInfo = PRICING.pro;
        // Annual here means Quarterly (3 months)
        basePrice = (cycle === "annual") ? (priceInfo.annual_per_month * 3) : priceInfo.monthly;
    } else if (tier === "pro_plus") {
        priceInfo = PRICING.pro_plus;
        basePrice = (cycle === "annual") ? (priceInfo.annual_per_month * 3) : priceInfo.monthly;
    } else {
        return res.status(400).json({ error: "Invalid tier" });
    }

    const discountAmount = (basePrice * priceInfo.discount) / 100;
    let finalAmount = basePrice - discountAmount; 

    // === COUPON APPLICATION ===
    if (couponCode) {
        if (validateCoupon(couponCode, user.email)) {
            finalAmount = finalAmount * 0.8; // 20% Discount
        }
    }

    let isUpgrade = false;
    let oldPlanCredit = 0.00;
     
    if (user.subscription.status === 'active' && 
        user.subscription.tier === 'pro' && 
        tier === 'pro_plus') {
        
        isUpgrade = true;
        let oldBasePrice = 0.00;
        if (user.subscription.cycle === 'monthly') {
            oldBasePrice = PRICING.pro.monthly;
        } else {
            oldBasePrice = PRICING.pro.annual_per_month * 3;
        }

        const oldDiscountAmount = (oldBasePrice * PRICING.pro.discount) / 100;
        oldPlanCredit = oldBasePrice - oldDiscountAmount;
        finalAmount = finalAmount - oldPlanCredit;
    }

    if (finalAmount < 0) finalAmount = 0;
    
    // Convert to INR
    const amountInINR = Math.floor(finalAmount * USD_TO_INR);
    const amountInPaise = amountInINR * 100; 

    const receiptId = `rcpt_${Date.now()}`;
    const options = { 
        amount: amountInPaise, 
        currency: "INR", 
        receipt: receiptId, 
        notes: { userId: googleId, tier, cycle, isUpgrade: isUpgrade, oldCredit: oldPlanCredit, couponCode: couponCode || "" } 
    };

    const order = await razorpay.orders.create(options);
    user.orders.push({ 
        orderId: order.id, 
        amount: amountInINR, 
        date: new Date(), 
        status: "created", 
        tier, 
        cycle, 
        receipt: receiptId, 
        currency: "INR" 
    });
    await user.save();

    res.json({ 
        order_id: order.id, 
        amount: amountInPaise, 
        currency: "INR", 
        key_id: RAZORPAY_KEY_ID, 
        user_name: user.name, 
        user_email: user.email, 
        user_contact: user.phone || "" 
    });
  } catch (err) {
    console.error("Payment Create Error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.post("/api/payment/verify", async (req, res) => {
  try {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body;
    const body = razorpay_order_id + "|" + razorpay_payment_id;
    const expectedSignature = crypto.createHmac("sha256", RAZORPAY_KEY_SECRET).update(body.toString()).digest("hex");

    if (expectedSignature === razorpay_signature) {
      const user = await User.findOne({ "orders.orderId": razorpay_order_id });
      if (!user) return res.status(404).json({ error: "Order not found" });
      const order = user.orders.find((o) => o.orderId === razorpay_order_id);
      
      try {
        const paymentDetails = await razorpay.payments.fetch(razorpay_payment_id);
        if(paymentDetails.contact && !user.phone) user.phone = paymentDetails.contact; 
        if(order) order.method = paymentDetails.method;
      } catch (e) {}

      user.subscription.status = "active";
      user.subscription.tier = order?.tier || "pro";
      user.subscription.cycle = order?.cycle || "monthly";
      user.subscription.isTrial = false; 
      
      // "Annual" variable used for Quarterly (90 days)
      const days = order?.cycle === "annual" ? 90 : 30;
      user.subscription.validUntil = new Date(Date.now() + days * 24 * 60 * 60 * 1000);

      if (order) { order.status = "paid"; order.paymentId = razorpay_payment_id; order.signature = razorpay_signature; }
      await user.save();
      return res.json({ status: "success", success: true });
    } else {
      return res.status(400).json({ status: "failure", success: false, error: "Invalid Signature" });
    }
  } catch (err) {
    res.status(500).json({ error: "Verification failed" });
  }
});

app.post("/api/payment/create-paypal-order", async (req, res) => {
  try {
    const { googleId, tier, cycle, couponCode } = req.body;
    const user = await User.findOne({ googleId });
    if (!user) return res.status(404).json({ error: "User not found" });

    let priceInfo;
    let basePrice = 0.00; 

    if (tier === "pro") {
        priceInfo = PRICING.pro;
        basePrice = (cycle === "annual") ? (priceInfo.annual_per_month * 3) : priceInfo.monthly;
    } else if (tier === "pro_plus") {
        priceInfo = PRICING.pro_plus;
        basePrice = (cycle === "annual") ? (priceInfo.annual_per_month * 3) : priceInfo.monthly;
    } else {
        return res.status(400).json({ error: "Invalid tier" });
    }

    const discountAmount = (basePrice * priceInfo.discount) / 100;
    let finalAmountUSD = basePrice - discountAmount; 

    // === COUPON APPLICATION ===
    if (couponCode) {
        if (validateCoupon(couponCode, user.email)) {
            finalAmountUSD = finalAmountUSD * 0.8; 
        }
    }

    let isUpgrade = false;
    let oldPlanCredit = 0.00;

    if (user.subscription.status === 'active' && 
        user.subscription.tier === 'pro' && 
        tier === 'pro_plus') {
        
        isUpgrade = true;
        let oldBasePrice = (user.subscription.cycle === 'monthly') ? PRICING.pro.monthly : (PRICING.pro.annual_per_month * 3);
        const oldDiscountAmount = (oldBasePrice * PRICING.pro.discount) / 100;
        oldPlanCredit = oldBasePrice - oldDiscountAmount;
        finalAmountUSD = finalAmountUSD - oldPlanCredit;
    }
     
    if (finalAmountUSD < 0.1) finalAmountUSD = 0.10; 
    
    const formattedAmountUSD = finalAmountUSD.toFixed(2);

    const accessToken = await getPayPalAccessToken();
    const orderRes = await fetch(`${PAYPAL_BASE_URL}/v2/checkout/orders`, {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${accessToken}`,
        },
        body: JSON.stringify({
            intent: "CAPTURE",
            purchase_units: [{
                amount: { currency_code: "USD", value: formattedAmountUSD },
                description: `${tier.toUpperCase()} Plan (${cycle})`
            }],
            application_context: {
                shipping_preference: "NO_SHIPPING", 
                user_action: "PAY_NOW",
                brand_name: "Whis AI"
            }
        })
    });

    const orderData = await orderRes.json();
    if (!orderRes.ok || !orderData.id) {
        console.error("❌ PayPal Order Failed:", JSON.stringify(orderData, null, 2));
        throw new Error("Failed to create PayPal Order");
    }

    user.orders.push({
        orderId: orderData.id,
        amount: parseFloat(formattedAmountUSD), 
        currency: "USD",
        date: new Date(),
        status: "created",
        tier,
        cycle,
        receipt: `pp_${Date.now()}`,
        method: "paypal",
        notes: { isUpgrade, couponCode }
    });
    await user.save();

    res.json({ id: orderData.id });

  } catch (err) {
    console.error("PayPal Create Error:", err);
    res.status(500).json({ error: "PayPal creation failed" });
  }
});

app.post("/api/payment/verify-paypal", async (req, res) => {
  try {
      const { orderID, googleId } = req.body;
      const user = await User.findOne({ googleId });
      if (!user) return res.status(404).json({ error: "User not found" });

      const dbOrder = user.orders.find(o => o.orderId === orderID);
      if (!dbOrder) return res.status(404).json({ error: "Order record not found" });

      const accessToken = await getPayPalAccessToken();
      const captureRes = await fetch(`${PAYPAL_BASE_URL}/v2/checkout/orders/${orderID}/capture`, {
          method: "POST",
          headers: {
              "Content-Type": "application/json",
              Authorization: `Bearer ${accessToken}`,
          }
      });
      
      const captureData = await captureRes.json();
      
      if (captureData.status === "COMPLETED") {
          dbOrder.status = "paid";
          dbOrder.paymentId = captureData.purchase_units[0].payments.captures[0].id;
          
          user.subscription.status = "active";
          user.subscription.tier = dbOrder.tier;
          user.subscription.cycle = dbOrder.cycle;
          user.subscription.isTrial = false; 
          
          // 90 days for quarterly
          const days = dbOrder.cycle === "annual" ? 90 : 30;
          user.subscription.validUntil = new Date(Date.now() + days * 24 * 60 * 60 * 1000);
          
          await user.save();
          res.json({ success: true });
      } else {
          res.status(400).json({ success: false, error: "Payment not completed" });
      }

  } catch (err) {
      console.error("PayPal Verify Error:", err);
      res.status(500).json({ error: "Verification Error" });
  }
});

app.post("/api/chat-stream", async (req, res) => {
  const googleId = req.headers["x-google-id"];
  
  if (!googleId) {
      return res.status(401).json({ error: "Unauthorized: Missing Google ID" });
  }
   
  const check = await checkAndIncrementUsage(googleId);
  if (!check.allowed) {
      res.setHeader("x-limit-reached", "true");
      return res.status(403).json({ error: "Limit reached" });
  }
  
  if(check.remaining !== undefined) {
      res.setHeader("x-remaining-free", check.remaining.toString());
  }

  const { conversationId, message } = req.body || {};
  if (!message || !message.role) return res.status(400).json({ error: "Invalid Body" });

  if (message.content && message.content.length > MAX_TEXT_CHAR_LIMIT) {
      message.content = message.content.slice(-MAX_TEXT_CHAR_LIMIT);
  }

  if (message.screenshot && googleId) {
      const screenCheck = await checkScreenshotLimit(googleId);
      if (!screenCheck.allowed) {
          return res.status(403).json({ error: screenCheck.error });
      }
  }

  let systemContextMessage = null;
  if (googleId) {
     const user = await User.findOne({ googleId }, { contexts: 1 });
     if (user && user.contexts) {
         const activeCtx = user.contexts.find(c => c.isActive);
         if (activeCtx) {
             systemContextMessage = {
                 role: "system",
                 content: `CRITICAL CONTEXT INSTRUCTION:\nThe user has provided the following specific context for this conversation (e.g., a resume, job description, or meeting notes).\nYou must adapt your answers to align with this context.\n\n=== CONTEXT START ===\n${activeCtx.content}\n=== CONTEXT END ===\n\nIf the user's query is unrelated to this context, answer normally but keep the context in mind if it becomes relevant.`
             };
         }
     }
  }

  const convId = conversationId || `conv_${Date.now()}`;

  let newMessage = { role: message.role, content: message.content };
  if (message.screenshot) {
    let sc = message.screenshot.startsWith("data:image") ? message.screenshot : `data:image/png;base64,${message.screenshot}`;
    newMessage = { 
        role: message.role, 
        content: [
            { type: "text", text: message.content || "Analyze screenshot." },
            { type: "image_url", image_url: { url: sc } }
        ]
    };
  }

  try {
    const conversation = await Conversation.findOneAndUpdate(
      { conversationId: convId },
      { 
        $push: { messages: newMessage },
        $set: { updatedAt: new Date(), userId: googleId }
      },
      { new: true, upsert: true }
    );
    
    const CONTEXT_WINDOW_SIZE = 10;
    const rawHistory = conversation.messages.slice(-CONTEXT_WINDOW_SIZE);

    const processedHistory = rawHistory.map((msg, index) => {
        if (index === rawHistory.length - 1) {
             return { role: msg.role, content: msg.content };
        }
        if (Array.isArray(msg.content)) {
             const textPart = msg.content.find(c => c.type === 'text');
             return {
                 role: msg.role,
                 content: textPart ? textPart.text : "[Screenshot sent]" 
             };
        }
        return { role: msg.role, content: msg.content };
    });

    const interviewSystemMsg = {
        role: "system",
        content: `You are an expert technical candidate in a high-stakes job interview. 
        Your goal is to provide the BEST POSSIBLE answer that ensures interview success.
        
        GUIDELINES:
        1. **Mode**: Answer as if YOU are the candidate.
        2. **Structure**: Summarize key points first. Be concise. The user needs to read this quickly and explain it verbally.
        3. **Sequence**: For technical questions, explain steps in the exact order an interviewer expects (e.g., Naive -> Optimized).
        4. **Clarity**: Make it easily understandable. Remove filler words.`
    };
    
    if (systemContextMessage) {
        processedHistory.unshift(systemContextMessage);
    }
    processedHistory.unshift(interviewSystemMsg);

    res.setHeader("x-conversation-id", convId);
    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    res.setHeader("Transfer-Encoding", "chunked");

    const openaiRes = await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      headers: { Authorization: `Bearer ${OPENAI_API_KEY}`, "Content-Type": "application/json" },
      body: JSON.stringify({ model: OPENAI_MODEL, messages: processedHistory, temperature: 0.6, stream: true })
    });

    if (!openaiRes.ok) {
        res.statusCode = 500;
        res.end(`OpenAI Error: ${openaiRes.status}`);
        return;
    }

    let fullAiResponse = "";
    const decoder = new TextDecoder();

    for await (const chunk of openaiRes.body) {
        const text = decoder.decode(chunk, { stream: true });
        const lines = text.split('\n');
        for (const line of lines) {
            if (line.startsWith('data: ') && line !== 'data: [DONE]') {
                try {
                    const json = JSON.parse(line.replace('data: ', ''));
                    const content = json.choices[0]?.delta?.content || "";
                    fullAiResponse += content;
                } catch (e) { }
            }
        }
        res.write(chunk); 
    }

    if (fullAiResponse) {
        await Conversation.updateOne(
            { conversationId: convId },
            { $push: { messages: { role: "assistant", content: fullAiResponse } } }
        );
    }

    res.end();
  } catch (err) {
    console.error("❌ [AI] Stream Error:", err);
    if (!res.headersSent) res.status(500).end("Internal Stream Error");
  }
});

app.post("/api/transcribe", upload.single("file"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: "Missing file" });
    const mime = req.file.mimetype || "audio/webm";
    const filename = req.file.originalname || "audio.webm";
    const formData = new FormData();
    formData.append("file", new Blob([req.file.buffer], { type: mime }), filename);
    formData.append("model", "whisper-1"); 
    formData.append("language", "en");

    const openaiRes = await fetch("https://api.openai.com/v1/audio/transcriptions", {
        method: "POST",
        headers: { Authorization: `Bearer ${OPENAI_API_KEY}` },
        body: formData
    });
    const data = await openaiRes.json();
    if (!openaiRes.ok) throw new Error(data.error?.message || "OpenAI Error");
    res.json({ text: data.text || "" });
  } catch (err) {
    res.status(500).json({ error: "Transcription failed" });
  }
});

app.post("/api/transcribe-draft", upload.single("file"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: "Missing file" });
    const mime = req.file.mimetype || "audio/webm";
    const filename = req.file.originalname || "audio.webm";
    const formData = new FormData();
    formData.append("file", new Blob([req.file.buffer], { type: mime }), filename);
    formData.append("model", "whisper-1"); 
    formData.append("language", "en");

    const openaiRes = await fetch("https://api.openai.com/v1/audio/transcriptions", {
        method: "POST",
        headers: { Authorization: `Bearer ${OPENAI_API_KEY}` },
        body: formData
    });
    const data = await openaiRes.json();
    if (!openaiRes.ok) throw new Error(data.error?.message || "OpenAI Error");
    
    res.json({ text: data.text || "" });
  } catch (err) {
    console.error("Draft Transcribe Error:", err);
    res.status(500).json({ error: "Draft Transcription failed" });
  }
});

app.post("/api/request-access", async (req, res) => {
  try {
    const { name, email, whatsapp, yoe, targetRole } = req.body;
    
    if (!name || !email || !whatsapp || !yoe) {
      return res.status(400).json({ error: "All mandatory fields must be filled." });
    }

    const ip = req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress;

    const newRequest = new FreeRequest({
      name,
      email,
      whatsapp,
      yoe,
      targetRole,
      ip
    });

    await newRequest.save();
    
    setTimeout(() => {
        res.json({ success: true, message: "Application Submitted Successfully" });
    }, 1000);

  } catch (err) {
    console.error("Free Request Error:", err);
    res.status(500).json({ error: "Submission failed. Try again." });
  }
});

app.get('*', (req, res, next) => {
  if (req.path.startsWith('/api')) return next();
  if (req.path.includes('.')) return next();
  if (req.path === '/') return res.sendFile(path.join(__dirname, 'index.html'));
  res.sendFile(path.join(__dirname, req.path + '.html'), (err) => { if (err) next(); });
});

app.listen(PORT, () => {
  console.log(`✅ Backend listening on http://localhost:${PORT}`);
});
