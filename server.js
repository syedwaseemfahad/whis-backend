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

// 5. Admin Config for Live Chat
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "admin123";

// 6. Telegram Notifications Config
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const TELEGRAM_CHAT_ID = process.env.TELEGRAM_CHAT_ID;

// --- LIMITS & TRIAL CONFIGURATION ---
const FREE_DAILY_LIMIT = parseInt(process.env.FREE_DAILY_LIMIT || "10", 10);
const FREE_SCREENSHOT_LIMIT = parseInt(process.env.FREE_SCREENSHOT_LIMIT || "3", 10);
const PAID_SCREENSHOT_LIMIT = parseInt(process.env.PAID_SCREENSHOT_LIMIT || "10", 10);
const MAX_TEXT_CHAR_LIMIT = parseInt(process.env.MAX_TEXT_CHAR_LIMIT || "4096", 10);

const MAX_TRIAL_SESSIONS = parseInt(process.env.MAX_TRIAL_SESSIONS || "3", 10);
const TRIAL_DURATION_MINUTES = 10; 

const PAID_MIC_LIMIT_MINUTES = parseInt(process.env.PAID_MIC_LIMIT_MINUTES || "300", 10);
const PAID_MIC_LIMIT_SECONDS = PAID_MIC_LIMIT_MINUTES * 60;

// --- PRICING CONFIGURATION ---
// Restored to exactly use your environment variables without overriding them.
const PRICING = {
  pro: {
    monthly: parseFloat(process.env.PRO_PER_MONTH), 
    quarterly: parseFloat(process.env.PRO_QUARTERLY),
    discount: parseFloat(process.env.PRO_DISCOUNT || 0)
  },
  pro_plus: {
    monthly: parseFloat(process.env.PROPLUS_PER_MONTH), 
    quarterly: parseFloat(process.env.PROPLUS_QUARTERLY),
    discount: parseFloat(process.env.PROPLUS_DISCOUNT || 0)
  }
};

// --- COUPON VALIDATOR ---
const getCouponDiscount = (code) => {
    if (!code) return 0;
    const c = code.toUpperCase();
    if (process.env.COUPON_10 && process.env.COUPON_10.toUpperCase() === c) return 10;
    if (process.env.COUPON_20 && process.env.COUPON_20.toUpperCase() === c) return 20;
    if (process.env.COUPON_30 && process.env.COUPON_30.toUpperCase() === c) return 30;
    if (process.env.COUPON_40 && process.env.COUPON_40.toUpperCase() === c) return 40;
    if (process.env.COUPON_50 && process.env.COUPON_50.toUpperCase() === c) return 50;
    if (process.env.COUPON_60 && process.env.COUPON_60.toUpperCase() === c) return 60;
    if (process.env.COUPON_70 && process.env.COUPON_70.toUpperCase() === c) return 70;
    if (process.env.COUPON_80 && process.env.COUPON_80.toUpperCase() === c) return 80;
    if (process.env.COUPON_90 && process.env.COUPON_90.toUpperCase() === c) return 90;
    return 0;
};

// --- INITIAL CHECKS ---
console.log("--- 🚀 STARTING SERVER ---");
console.log(`--- 📊 LIMITS: FreeChat=${FREE_DAILY_LIMIT}, MaxTrialSessions=${MAX_TRIAL_SESSIONS} ---`);

if (!OPENAI_API_KEY) console.error("⚠️  MISSING: OPENAI_API_KEY");
if (!RAZORPAY_KEY_ID) console.error("⚠️  MISSING: RAZORPAY_KEY_ID");
if (!PAYPAL_CLIENT_ID) console.error("⚠️  MISSING: PAYPAL_CLIENT_ID");
if (!GOOGLE_CLIENT_ID) console.error("⚠️  MISSING: GOOGLE_CLIENT_ID");
if (!GOOGLE_CLIENT_SECRET) console.error("⚠️  MISSING: GOOGLE_CLIENT_SECRET");
if (!TELEGRAM_BOT_TOKEN || !TELEGRAM_CHAT_ID) console.log("⚠️  TELEGRAM NOTIFICATIONS: Disabled (Missing credentials)");

if (isNaN(PRICING.pro.monthly) || isNaN(PRICING.pro_plus.monthly)) {
    console.error("❌ CRITICAL: Pricing Environment Variables are missing or invalid!");
}

const razorpay = new Razorpay({
  key_id: RAZORPAY_KEY_ID || "dummy",
  key_secret: RAZORPAY_KEY_SECRET || "dummy",
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
  currentSessionId: { type: String, default: "" },
  subscription: {
    status: { type: String, enum: ["active", "inactive", "past_due"], default: "inactive" },
    tier: { type: String, enum: ["free", "pro", "pro_plus"], default: "free" },
    cycle: { type: String, enum: ["monthly", "quarterly", "annual"], default: "monthly" },
    validUntil: Date,
    isTrial: { type: Boolean, default: false }
  },
  trialUsage: { count: { type: Number, default: 0 } },
  freeUsage: { count: { type: Number, default: 0 }, lastDate: { type: String } },
  screenshotUsage: { count: { type: Number, default: 0 }, lastDate: { type: String } },
  micUsage: { monthKey: { type: String }, secondsUsed: { type: Number, default: 0 } },
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

const enterpriseQuerySchema = new mongoose.Schema({
  email: { type: String, required: true },
  mobile: { type: String, required: true },
  query: { type: String, required: true },
  timestamp: { type: Date, default: Date.now }
});
const EnterpriseQuery = mongoose.model("EnterpriseQuery", enterpriseQuerySchema);

// --- NEW FEATURE: LIVE CHAT SUPPORT SCHEMA ---
const chatMessageSchema = new mongoose.Schema({
  email: { type: String, required: true },
  isSupport: { type: Boolean, default: false }, 
  text: { type: String, required: true },
  timestamp: { type: Date, default: Date.now },
  read: { type: Boolean, default: false }
});
const ChatMessage = mongoose.model("ChatMessage", chatMessageSchema);


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
      console.log(`[Sub] Expired for ${googleId}. Downgrading to free.`);
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
      { googleId: googleId, "freeUsage.count": { $lt: FREE_DAILY_LIMIT } },
      { $inc: { "freeUsage.count": 1 } },
      { new: true }
  );

  if (result) {
      return { allowed: true, tier: 'free', remaining: FREE_DAILY_LIMIT - result.freeUsage.count };
  } else {
      return { allowed: false, error: "Daily limit reached" };
  }
}

function getMonthKey(d = new Date()) {
  const year = d.getUTCFullYear();
  const month = String(d.getUTCMonth() + 1).padStart(2, "0");
  return `${year}-${month}`;
}

function isPaidMicEnforced(user) {
  return (
    user && user.subscription && user.subscription.status === "active" &&
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
        { googleId: googleId, "screenshotUsage.count": { $lt: limit } },
        { $inc: { "screenshotUsage.count": 1 }, $set: { "screenshotUsage.lastDate": today } },
        { new: true }
    );

    if (result) {
        return { allowed: true, count: result.screenshotUsage.count, limit };
    } else {
        return { allowed: false, error: isPaid ? `Daily screenshot limit (${limit}) reached.` : `Free daily screenshot limit (${limit}) reached.` };
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
    
    // --- ABANDONED CART RECOVERY HOOK ---
    setTimeout(async () => {
        try {
            const freshUser = await User.findOne({ googleId });
            if (freshUser && freshUser.subscription.tier === 'free' && freshUser.orders.length === 0) {
                console.log(`🛒 [ABANDONED CART] Triggering recovery for: ${freshUser.email}`);
            }
        } catch (e) {
            console.error("Abandoned cart check failed:", e);
        }
    }, 3600000); // 1 hour
    
    res.json({ success: true, user, tokens: { id_token: idToken, access_token: accessToken } });
  } catch (err) {
    console.error("Auth Error:", err);
    res.status(500).json({ error: "Database or Auth error" });
  }
});

app.post("/api/user/update-phone", async (req, res) => {
  try {
    const { googleId, phone } = req.body;
    if (!googleId || !phone) return res.status(400).json({ error: "Missing required fields" });

    const updatedUser = await User.findOneAndUpdate(
      { googleId: googleId },
      { phone: phone },
      { new: true }
    );

    if (!updatedUser) return res.status(404).json({ error: "User not found" });
    res.json({ success: true, user: updatedUser });
  } catch (err) {
    console.error("Update Phone Error:", err);
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
        res.json({ success: true, validUntil: expiry, sessionsUsed: user.trialUsage.count, maxSessions: MAX_TRIAL_SESSIONS });
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
        await User.findOneAndUpdate({ googleId }, { currentSessionId: newSessionId });
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
      orders: user.orders ? user.orders.sort((a,b) => new Date(b.date) - new Date(a.date)) : []
    });
  } catch (err) {
    res.status(500).json({ error: "Failed to check status" });
  }
});

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

    if (isActive) user.contexts.forEach(c => c.isActive = false);

    const existingIndex = user.contexts.findIndex(c => c.id === id);

    if (existingIndex > -1) {
      user.contexts[existingIndex].name = name;
      user.contexts[existingIndex].content = content;
      if (isActive !== undefined) user.contexts[existingIndex].isActive = isActive;
      user.contexts[existingIndex].updatedAt = new Date();
    } else {
      if (user.contexts.length >= 10) return res.status(400).json({ error: "Context limit reached (Max 10)" });
      user.contexts.push({ id: id || crypto.randomUUID(), name, content, isActive: !!isActive, updatedAt: new Date() });
    }

    await user.save();
    res.json({ success: true, contexts: user.contexts });
  } catch (err) {
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

    await User.updateOne({ googleId }, { $pull: { contexts: { id: contextId } } });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: "Failed to delete" });
  }
});

// --- COUPON VALIDATION API ---
app.post("/api/payment/validate-coupon", (req, res) => {
    const { coupon } = req.body;
    const discount = getCouponDiscount(coupon);
    if (discount > 0) {
        res.json({ success: true, discount });
    } else {
        res.json({ success: false, error: "Invalid coupon code" });
    }
});

// --- ENTERPRISE FORM API ---
app.post("/api/enterprise-query", async (req, res) => {
    try {
        const { email, mobile, query } = req.body;
        if (!email || !mobile || !query) return res.status(400).json({ error: "Missing fields" });

        const doc = new EnterpriseQuery({ email, mobile, query });
        await doc.save();
        res.json({ success: true });
    } catch(e) {
        console.error("Enterprise Query Error:", e);
        res.status(500).json({ error: "Failed to save inquiry" });
    }
});

// ================= LIVE CHAT SUPPORT ROUTES =================

app.get("/api/chat/history/:email", async (req, res) => {
    try {
        const email = req.params.email;
        const messages = await ChatMessage.find({ email }).sort({ timestamp: 1 });
        res.json({ success: true, messages });
    } catch (err) {
        res.status(500).json({ error: "Failed to fetch chat history" });
    }
});

app.post("/api/chat/send", async (req, res) => {
    try {
        const { email, text } = req.body;
        if (!email || !text) return res.status(400).json({ error: "Missing fields" });
        
        // 1. Save the user's message
        const userMsg = new ChatMessage({ email, text, isSupport: false });
        await userMsg.save();

        // 2. Instantly notify Admin via Telegram (so they can monitor or jump in)
        if (TELEGRAM_BOT_TOKEN && TELEGRAM_CHAT_ID) {
            const adminDashboardLink = `https://whis-ai.com/admin`; 
            const telegramMsg = `🚨 *New Support Chat*\n*User:* ${email}\n*Message:* ${text}\n\n🤖 _AI Support Agent is replying..._\n[Open Admin Panel](${adminDashboardLink})`;
            
            fetch(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ 
                    chat_id: TELEGRAM_CHAT_ID, 
                    text: telegramMsg, 
                    parse_mode: 'Markdown' 
                })
            }).catch(e => console.error("Telegram notification failed:", e.message));
        }

        // 3. Fetch recent conversation history for AI context
        const recentChats = await ChatMessage.find({ email }).sort({ timestamp: -1 }).limit(8);
        recentChats.reverse(); // put in chronological order

        const couponCode = process.env.COUPON_20 || "WHIS20";

        // *** UPDATED HUMANIZED PROMPT FOR FAST TYPING ***
        const messagesForAI = [
            {
                role: "system",
                content: `You are 'Alex', a friendly, helpful, and empathetic customer success manager for Whis-AI (an invisible interview copilot app).
Your goal is to chat with users, build trust, and help them with questions about features, pricing, troubleshooting, and setup.

Act completely human. Do not sound like a bot, an AI, or an automated system. Use conversational language, a warm tone, and occasional natural phrases like "I totally understand," "Happy to help," or "Let me check that for you."

KNOWLEDGE BASE:
- Product: Whis-AI (Desktop app for macOS and Windows).
- Core Features: 
  1. Voice Capture (Listens to interviews in real-time).
  2. Screen Vision (Sees coding questions automatically).
  3. 100% Invisible (Ghost Mode makes it completely hidden from Zoom/Teams/Meet screen sharing).
  4. Smart Context (Users can upload Resumes or Job Descriptions to get tailored answers).
  5. Universal Translator (Understands foreign languages, answers in English).
- Pricing: 
  - Free Tier: 10 daily answers, normal speed. 
  - Pro Professional: 8 hours mic access/month, unlimited answers, screen reading tool. 
  - Elite Stealth: 100% undetectable, ghost mode, hidden app process.
- Subscriptions: Available in Monthly and Quarterly (Quarterly saves 51%).
- Money-back Guarantee: 7 days, no questions asked.

RULES:
1. NEVER reveal you are an AI, bot, or automated system. You are a real person named Alex.
2. NEVER reveal technical backend details (e.g., do not say you use Electron, Node.js, MongoDB, React, or GPT).
3. Keep answers conversational, natural, and friendly. 
4. Do not invent features or prices not listed here.
5. **DISCOUNT RULE**: If the user mentions they are struggling with budget, unemployed, asking for a scholarship, discount, or coupon, be empathetic. Say something like: "I completely understand how tough the job market is right now. I'd love to help out. You can use the code ${couponCode} at checkout for a 20% discount!"

CRITICAL CHAT FORMATTING RULE:
To simulate a real human typing quickly on a live chat, you MUST break your response into 2 to 4 short, rapid-fire messages. 
Separate each chat bubble using the exact string "|||". 
Example:
Hi there! Happy to help. ||| Give me just a second to pull up that info for you. ||| Okay, you just need to restart your app to see the changes!`
            }
        ];

        recentChats.forEach(c => {
            messagesForAI.push({
                role: c.isSupport ? "assistant" : "user",
                content: c.text
            });
        });

        // 4. Call OpenAI API for the response
        try {
            const openaiRes = await fetch("https://api.openai.com/v1/chat/completions", {
                method: "POST",
                headers: { 
                    Authorization: `Bearer ${OPENAI_API_KEY}`, 
                    "Content-Type": "application/json" 
                },
                body: JSON.stringify({ 
                    model: OPENAI_MODEL, 
                    messages: messagesForAI, 
                    temperature: 0.7,
                    max_tokens: 250
                })
            });

            if (openaiRes.ok) {
                const aiData = await openaiRes.json();
                const aiResponseText = aiData.choices[0].message.content;

                // Robust chunk splitting
                let chunks = [];
                if (aiResponseText.includes('|||')) {
                    chunks = aiResponseText.split('|||');
                } else if (aiResponseText.includes('\n\n')) {
                    chunks = aiResponseText.split('\n\n');
                } else {
                    chunks = [aiResponseText];
                }
                
                chunks = chunks.map(s => s.trim()).filter(s => s);

                // Save the first chunk immediately to provide instant feedback
                const firstMsgText = chunks.shift() || "Hello!";
                const aiMsg = new ChatMessage({ email, text: firstMsgText, isSupport: true });
                await aiMsg.save();

                // Process the remaining chunks asynchronously to simulate a fast human typer
                if (chunks.length > 0) {
                    let currentDelay = 0;
                    chunks.forEach((chunkText) => {
                        // Base delay of 1.5 seconds + 25ms per character to simulate rapid typing
                        const typingTime = 1500 + (chunkText.length * 25);
                        currentDelay += typingTime;
                        
                        setTimeout(async () => {
                            try {
                                const delayedMsg = new ChatMessage({ email, text: chunkText, isSupport: true });
                                await delayedMsg.save();
                            } catch(e) { 
                                console.error("Delayed message save error:", e); 
                            }
                        }, currentDelay);
                    });
                }

                return res.json({ success: true, message: userMsg, aiReply: aiMsg });
            }
        } catch (aiError) {
            console.error("AI Auto-reply error:", aiError);
        }

        // Fallback if AI fails: just return success for the user's message
        res.json({ success: true, message: userMsg });

    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Failed to send message" });
    }
});

// Admin chat endpoints
app.post("/api/admin/login", (req, res) => {
    const { password } = req.body;
    if (password === ADMIN_PASSWORD) res.json({ success: true });
    else res.status(401).json({ success: false, error: "Invalid password" });
});

app.get("/api/admin/chats", async (req, res) => {
    try {
        const chats = await ChatMessage.aggregate([
            { $sort: { timestamp: -1 } },
            { $group: {
                _id: "$email",
                latestMessage: { $first: "$text" },
                timestamp: { $first: "$timestamp" },
                unreadCount: { 
                    $sum: { 
                        $cond: [{ $and: [{ $eq: ["$read", false] }, { $eq: ["$isSupport", false] }] }, 1, 0] 
                    } 
                }
            }},
            { $sort: { timestamp: -1 } }
        ]);
        res.json({ success: true, chats });
    } catch (err) {
        res.status(500).json({ error: "Failed to fetch chats" });
    }
});

app.post("/api/admin/send", async (req, res) => {
    try {
        const { email, text, password } = req.body;
        if (password !== ADMIN_PASSWORD) return res.status(401).json({ error: "Unauthorized" });
        if (!email || !text) return res.status(400).json({ error: "Missing fields" });

        const msg = new ChatMessage({ email, text, isSupport: true });
        await msg.save();
        res.json({ success: true, message: msg });
    } catch (err) {
        res.status(500).json({ error: "Failed to send message" });
    }
});

app.post("/api/admin/mark-read", async (req, res) => {
    try {
        const { email, password } = req.body;
        if (password !== ADMIN_PASSWORD) return res.status(401).json({ error: "Unauthorized" });
        
        await ChatMessage.updateMany(
            { email, isSupport: false, read: false }, 
            { $set: { read: true } }
        );
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: "Failed to mark as read" });
    }
});


// ================= PAYMENT ROUTES =================

app.post("/api/payment/create-order", async (req, res) => {
  try {
    const { googleId, tier, cycle, couponCode } = req.body; 
    const user = await User.findOne({ googleId });
    if (!user) return res.status(404).json({ error: "User not found" });

    let priceInfo;
    let basePrice = 0.00; 
     
    if (tier === "pro") {
        priceInfo = PRICING.pro;
        basePrice = (cycle === "quarterly") ? priceInfo.quarterly : priceInfo.monthly;
    } else if (tier === "pro_plus") {
        priceInfo = PRICING.pro_plus;
        basePrice = (cycle === "quarterly") ? priceInfo.quarterly : priceInfo.monthly;
    } else {
        return res.status(400).json({ error: "Invalid tier" });
    }

    const discountAmount = (basePrice * priceInfo.discount) / 100;
    let finalAmount = basePrice - discountAmount; 

    let isUpgrade = false;
    let oldPlanCredit = 0.00;
     
    if (user.subscription.status === 'active' && user.subscription.tier === 'pro' && tier === 'pro_plus') {
        isUpgrade = true;
        let oldBasePrice = (user.subscription.cycle === 'monthly') ? PRICING.pro.monthly : PRICING.pro.quarterly;
        const oldDiscountAmount = (oldBasePrice * PRICING.pro.discount) / 100;
        oldPlanCredit = oldBasePrice - oldDiscountAmount;
        finalAmount = finalAmount - oldPlanCredit;
    }

    const couponDisc = getCouponDiscount(couponCode);
    if (couponDisc > 0) {
        finalAmount = finalAmount - (finalAmount * couponDisc / 100);
    }

    if (finalAmount < 0) finalAmount = 0;
    
    const amountInINR = Math.floor(finalAmount * USD_TO_INR);
    const amountInPaise = amountInINR * 100; 

    const receiptId = `rcpt_${Date.now()}`;
    const options = { 
        amount: amountInPaise, 
        currency: "INR", 
        receipt: receiptId, 
        notes: { userId: googleId, tier, cycle, isUpgrade: isUpgrade, oldCredit: oldPlanCredit, basePriceUSD: basePrice, couponApplied: couponCode || 'None' } 
    };

    const order = await razorpay.orders.create(options);
    user.orders.push({ 
        orderId: order.id, amount: amountInINR, date: new Date(), 
        status: "created", tier, cycle, receipt: receiptId, currency: "INR" 
    });
    await user.save();

    res.json({ 
        order_id: order.id, amount: amountInPaise, currency: "INR", 
        key_id: RAZORPAY_KEY_ID, user_name: user.name, user_email: user.email, user_contact: user.phone || "" 
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
      
      const days = order?.cycle === "quarterly" ? 90 : 30; // updated to quarterly
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
        basePrice = (cycle === "quarterly") ? priceInfo.quarterly : priceInfo.monthly;
    } else if (tier === "pro_plus") {
        priceInfo = PRICING.pro_plus;
        basePrice = (cycle === "quarterly") ? priceInfo.quarterly : priceInfo.monthly;
    } else {
        return res.status(400).json({ error: "Invalid tier" });
    }

    const discountAmount = (basePrice * priceInfo.discount) / 100;
    let finalAmountUSD = basePrice - discountAmount; 

    let isUpgrade = false;
    let oldPlanCredit = 0.00;

    if (user.subscription.status === 'active' && user.subscription.tier === 'pro' && tier === 'pro_plus') {
        isUpgrade = true;
        let oldBasePrice = (user.subscription.cycle === 'monthly') ? PRICING.pro.monthly : PRICING.pro.quarterly;
        const oldDiscountAmount = (oldBasePrice * PRICING.pro.discount) / 100;
        oldPlanCredit = oldBasePrice - oldDiscountAmount;
        finalAmountUSD = finalAmountUSD - oldPlanCredit;
    }

    // --- APPLY COUPON ---
    const couponDisc = getCouponDiscount(couponCode);
    if (couponDisc > 0) {
        finalAmountUSD = finalAmountUSD - (finalAmountUSD * couponDisc / 100);
    }
     
    if (finalAmountUSD < 0.1) finalAmountUSD = 0.10; 
    
    const formattedAmountUSD = finalAmountUSD.toFixed(2);

    const accessToken = await getPayPalAccessToken();
    const orderRes = await fetch(`${PAYPAL_BASE_URL}/v2/checkout/orders`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${accessToken}` },
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
        throw new Error("Failed to create PayPal Order");
    }

    user.orders.push({
        orderId: orderData.id, amount: parseFloat(formattedAmountUSD), currency: "USD",
        date: new Date(), status: "created", tier, cycle, receipt: `pp_${Date.now()}`,
        method: "paypal", notes: { isUpgrade, couponApplied: couponCode || 'None' }
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
          headers: { "Content-Type": "application/json", Authorization: `Bearer ${accessToken}` }
      });
      
      const captureData = await captureRes.json();
      
      if (captureData.status === "COMPLETED") {
          dbOrder.status = "paid";
          dbOrder.paymentId = captureData.purchase_units[0].payments.captures[0].id;
          
          user.subscription.status = "active";
          user.subscription.tier = dbOrder.tier;
          user.subscription.cycle = dbOrder.cycle;
          user.subscription.isTrial = false; 
          
          const days = dbOrder.cycle === "quarterly" ? 90 : 30; // updated to quarterly
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
  
  if (!googleId) return res.status(401).json({ error: "Unauthorized: Missing Google ID" });
   
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
      if (!screenCheck.allowed) return res.status(403).json({ error: screenCheck.error });
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
      { $push: { messages: newMessage }, $set: { updatedAt: new Date(), userId: googleId } },
      { new: true, upsert: true }
    );
    
    const CONTEXT_WINDOW_SIZE = 10;
    const rawHistory = conversation.messages.slice(-CONTEXT_WINDOW_SIZE);

    const processedHistory = rawHistory.map((msg, index) => {
        if (index === rawHistory.length - 1) return { role: msg.role, content: msg.content };
        if (Array.isArray(msg.content)) {
             const textPart = msg.content.find(c => c.type === 'text');
             return { role: msg.role, content: textPart ? textPart.text : "[Screenshot sent]" };
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
    
    if (systemContextMessage) processedHistory.unshift(systemContextMessage);
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
        method: "POST", headers: { Authorization: `Bearer ${OPENAI_API_KEY}` }, body: formData
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
        method: "POST", headers: { Authorization: `Bearer ${OPENAI_API_KEY}` }, body: formData
    });
    const data = await openaiRes.json();
    if (!openaiRes.ok) throw new Error(data.error?.message || "OpenAI Error");
    res.json({ text: data.text || "" });
  } catch (err) {
    res.status(500).json({ error: "Draft Transcription failed" });
  }
});

app.post("/api/request-access", async (req, res) => {
  try {
    const { name, email, whatsapp, yoe, targetRole } = req.body;
    if (!name || !email || !whatsapp || !yoe) return res.status(400).json({ error: "All mandatory fields must be filled." });
    const ip = req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress;

    const newRequest = new FreeRequest({ name, email, whatsapp, yoe, targetRole, ip });
    await newRequest.save();
    
    setTimeout(() => { res.json({ success: true, message: "Application Submitted Successfully" }); }, 1000);
  } catch (err) {
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
