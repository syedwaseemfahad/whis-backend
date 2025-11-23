// backend/server.js
require("dotenv").config();

const express = require("express");
const cors = require("cors");
const multer = require("multer");
const mongoose = require("mongoose");
// If using Node < 18, uncomment: const fetch = require("node-fetch");

// --- CONFIGURATION ---
const PORT = process.env.PORT || 4000;
const OPENAI_API_KEY = process.env.OPENAI_API_KEY;
const MONGODB_URI = process.env.MONGODB_URI || "mongodb://localhost:27017/whis-app";

// The URL where your frontend is hosted (for payment redirects)
const UI_API = process.env.UI_API || "http://localhost:5500"; 

// Cashfree Config
const CASHFREE_APP_ID = process.env.CASHFREE_APP_ID;
const CASHFREE_SECRET_KEY = process.env.CASHFREE_SECRET_KEY;
const CASHFREE_ENV = process.env.CASHFREE_ENV || "SANDBOX";
const CASHFREE_URL = CASHFREE_ENV === "PRODUCTION"
    ? "https://api.cashfree.com/pg"
    : "https://sandbox.cashfree.com/pg";

if (!OPENAI_API_KEY) {
  console.error("⚠️ OPENAI_API_KEY missing in backend/.env");
}

// Multer setup (using memory storage to handle buffers for OpenAI)
const upload = multer({ storage: multer.memoryStorage() });
const app = express();

app.use(cors());
// Increased limit to 50mb to handle high-res screenshots without crashing
app.use(express.json({ limit: "50mb" }));

// --- 1. MongoDB Connection ---
mongoose
  .connect(MONGODB_URI)
  .then(() => console.log("✅ Connected to MongoDB"))
  .catch((err) => console.error("❌ MongoDB connection error:", err));

// --- 2. User Schema ---
const userSchema = new mongoose.Schema({
  googleId: { type: String, unique: true, required: true },
  email: { type: String, required: true },
  name: String,
  avatarUrl: String,
  subscription: {
    status: { type: String, enum: ["active", "inactive", "past_due"], default: "inactive" },
    tier: { type: String, enum: ["free", "pro", "pro_plus"], default: "free" },
    cycle: { type: String, enum: ["monthly", "annual"], default: "monthly" },
    validUntil: Date
  },
  freeUsage: {
    count: { type: Number, default: 0 },
    lastDate: { type: String } // Format: YYYY-MM-DD
  },
  orders: [
    {
      orderId: String,
      amount: Number,
      date: Date,
      status: String,
      tier: String, 
      cycle: String 
    }
  ],
  createdAt: { type: Date, default: Date.now },
  lastLogin: Date
});

const User = mongoose.model("User", userSchema);

// Helper: Tier Value for comparison
const TIER_LEVELS = { "free": 0, "pro": 1, "pro_plus": 2 };

// --------- Middleware ---------
app.use((req, res, next) => {
  // Allow these routes without custom checks (Auth is handled inside them)
  if (
    req.path.startsWith("/api/auth") ||
    req.path.startsWith("/api/user") ||
    req.path.startsWith("/api/payment")
  ) {
    return next();
  }
  if (req.method === "OPTIONS") return next();
  next();
});

const conversations = new Map();

// --- Helper: Usage Check ---
async function checkAndIncrementUsage(googleId) {
  const today = new Date().toISOString().slice(0, 10);
  const user = await User.findOne({ googleId });
  
  if (!user) return { allowed: false, error: "User not found" };

  // Check Paid Status
  if (user.subscription.status === 'active' && ['pro', 'pro_plus'].includes(user.subscription.tier)) {
     if (user.subscription.validUntil && new Date() > user.subscription.validUntil) {
         // Expired
         user.subscription.status = 'inactive';
         user.subscription.tier = 'free';
         await user.save();
     } else {
         // Active
         return { allowed: true, tier: user.subscription.tier };
     }
  }

  // Free Tier Logic
  if (user.freeUsage.lastDate !== today) {
    user.freeUsage.count = 0;
    user.freeUsage.lastDate = today;
  }

  // UPDATED LIMIT: 10 per day
  if (user.freeUsage.count >= 10) {
    return { allowed: false, error: "Daily limit reached" };
  }

  user.freeUsage.count += 1;
  await user.save();
  
  return { allowed: true, tier: 'free', remaining: 10 - user.freeUsage.count };
}

// ================= ROUTES =================

// 1. AUTH
app.post("/api/auth/google", async (req, res) => {
  try {
    const { token } = req.body;
    const googleRes = await fetch(`https://oauth2.googleapis.com/tokeninfo?id_token=${token}`);
    if (!googleRes.ok) return res.status(401).json({ error: "Invalid Google Token" });

    const payload = await googleRes.json();
    const { sub: googleId, email, name, picture: avatarUrl } = payload;

    const user = await User.findOneAndUpdate(
      { googleId },
      { 
        email, name, avatarUrl, lastLogin: new Date(),
        $setOnInsert: {
          "subscription.status": "inactive",
          "subscription.tier": "free",
          "freeUsage.count": 0,
          "freeUsage.lastDate": new Date().toISOString().slice(0, 10)
        }
      },
      { new: true, upsert: true }
    );
    res.json({ success: true, user });
  } catch (err) {
    res.status(500).json({ error: "Database error" });
  }
});

// 2. USER STATUS
app.get("/api/user/status", async (req, res) => {
  try {
    const googleId = req.headers["x-google-id"];
    if (!googleId) return res.status(401).json({ error: "Not authenticated" });

    const user = await User.findOne({ googleId });
    if (!user) return res.json({ active: false, tier: null });

    const isActive = user.subscription.status === "active";
    if (isActive && user.subscription.validUntil && new Date() > user.subscription.validUntil) {
      user.subscription.status = "inactive";
      user.subscription.tier = "free";
      await user.save();
      return res.json({ active: false, tier: "free", expired: true, freeUsage: user.freeUsage, orders: user.orders });
    }

    res.json({
      active: user.subscription.status === "active",
      tier: user.subscription.tier,
      validUntil: user.subscription.validUntil,
      freeUsage: user.freeUsage,
      orders: user.orders ? user.orders.sort((a,b) => new Date(b.date) - new Date(a.date)) : []
    });
  } catch (err) {
    res.status(500).json({ error: "Failed to check status" });
  }
});

// 3. CREATE PAYMENT (Updated Pricing & Protection)
app.post("/api/payment/create-order", async (req, res) => {
  try {
    const { googleId, tier, cycle } = req.body; 
    const user = await User.findOne({ googleId });
    if (!user) return res.status(404).json({ error: "User not found" });

    // 1. Prevent Downgrade or Same-Tier Purchase
    const currentTier = (user.subscription.status === 'active') ? user.subscription.tier : "free";
    const currentLevel = TIER_LEVELS[currentTier];
    const requestedLevel = TIER_LEVELS[tier];

    if (user.subscription.status === 'active' && requestedLevel <= currentLevel) {
        return res.status(400).json({ error: `You are already on the ${currentTier.replace('_', ' ')} plan. You cannot purchase the same or lower tier.` });
    }

    // 2. Pricing Logic
    let amount = 1.0;
    if (tier === "pro") {
        // Pro Monthly: 799, Annual: 499 * 12 = 5988
        amount = (cycle === "annual") ? 5988.0 : 799.0;
    } else if (tier === "pro_plus") {
        // Stealth Monthly: 2499, Annual: 999 * 12 = 11988
        amount = (cycle === "annual") ? 11988.0 : 2499.0;
    }

    const orderId = `order_${Date.now()}_${Math.floor(Math.random() * 1000)}`;

    const response = await fetch(`${CASHFREE_URL}/orders`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-version": "2023-08-01",
        "x-client-id": CASHFREE_APP_ID,
        "x-client-secret": CASHFREE_SECRET_KEY
      },
      body: JSON.stringify({
        order_id: orderId,
        order_amount: amount,
        order_currency: "INR",
        customer_details: { customer_id: googleId, customer_email: user.email, customer_phone: "9999999999" },
        order_meta: { return_url: `${UI_API}/payment.html?order_id=${orderId}` }
      })
    });

    const data = await response.json();
    if (!response.ok) return res.status(500).json({ error: data.message });

    user.orders.push({ orderId, amount, date: new Date(), status: "PENDING", tier, cycle });
    await user.save();

    res.json({ payment_session_id: data.payment_session_id, order_id: orderId });
  } catch (err) {
    res.status(500).json({ error: "Internal server error" });
  }
});

// 4. VERIFY PAYMENT
app.post("/api/payment/verify", async (req, res) => {
  try {
    const { orderId } = req.body;
    const response = await fetch(`${CASHFREE_URL}/orders/${orderId}`, {
      headers: { "x-api-version": "2023-08-01", "x-client-id": CASHFREE_APP_ID, "x-client-secret": CASHFREE_SECRET_KEY }
    });
    const data = await response.json();

    if (data.order_status === "PAID") {
      const user = await User.findOne({ "orders.orderId": orderId });
      if (user) {
        const order = user.orders.find((o) => o.orderId === orderId);
        user.subscription.status = "active";
        user.subscription.tier = order?.tier || "pro";
        const days = order?.cycle === "annual" ? 365 : 30;
        user.subscription.validUntil = new Date(Date.now() + days * 24 * 60 * 60 * 1000);
        if (order) order.status = "PAID";
        await user.save();
        return res.json({ status: "PAID", success: true });
      }
    }
    res.json({ status: data.order_status, success: false });
  } catch (err) {
    res.status(500).json({ error: "Verification failed" });
  }
});

// ==========================================
//  AI & TRANSCRIPTION APIs
// ==========================================

// 5. STREAM CHAT (With 400 Error Fix & Full Stream Logic)
app.post("/api/chat-stream", async (req, res) => {
  const googleId = req.headers["x-google-id"];
  
  if (googleId) {
    const check = await checkAndIncrementUsage(googleId);
    if (!check.allowed) return res.status(403).json({ error: "Daily limit reached. Please upgrade to Pro." });
  }

  const { conversationId, message } = req.body || {};
  const role = message?.role;
  const content = message?.content;
  let screenshot = message?.screenshot;

  if (!role || (!content && !screenshot)) {
    return res.status(400).json({ error: "Invalid Body" });
  }

  // *** FIX: Ensure Data URI for OpenAI ***
  if (screenshot && !screenshot.startsWith("data:image")) {
      // Append the prefix if missing (assuming PNG as standard for screenshots)
      screenshot = `data:image/png;base64,${screenshot}`;
  }

  let convId = conversationId || `conv_${Date.now()}`;
  const history = conversations.get(convId) || [];

  let newMessage;
  if (screenshot) {
    const parts = [];
    // Always provide a text prompt for context if user didn't type one
    if (content) parts.push({ type: "text", text: content });
    else parts.push({ type: "text", text: "Analyze this screenshot contextually." });
    
    parts.push({ type: "image_url", image_url: { url: screenshot } });
    newMessage = { role, content: parts };
  } else {
    newMessage = { role, content };
  }

  history.push(newMessage);
  conversations.set(convId, history);

  res.setHeader("x-conversation-id", convId);
  res.setHeader("Content-Type", "text/plain; charset=utf-8");
  res.setHeader("Transfer-Encoding", "chunked");

  try {
    const openaiRes = await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${OPENAI_API_KEY}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        model: "gpt-4o-mini",
        messages: history,
        temperature: 0.6,
        stream: true
      })
    });

    if (!openaiRes.ok) {
      const errText = await openaiRes.text();
      console.error("OpenAI stream error:", openaiRes.status, errText);
      res.statusCode = 500;
      res.end(`OpenAI Error: ${openaiRes.status} - ${errText}`);
      return;
    }

    for await (const chunk of openaiRes.body) {
      res.write(chunk);
    }
    res.end();
  } catch (err) {
    console.error("Stream Error:", err);
    res.statusCode = 500;
    res.end("Internal Stream Error");
  }
});

// 6. TRANSCRIPTION
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
    console.error("Transcribe Error:", err);
    res.status(500).json({ error: "Transcription failed" });
  }
});

app.listen(PORT, () => {
  console.log(`✅ Backend listening on http://localhost:${PORT}`);
});
