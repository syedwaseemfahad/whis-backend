require("dotenv").config();

const express = require("express");
const cors = require("cors");
const multer = require("multer");
const mongoose = require("mongoose");
const Razorpay = require("razorpay");
const crypto = require("crypto");
const path = require("path");
const url = require("url"); // Native node module for parsing URLs

// --- CONFIGURATION ---
const PORT = process.env.PORT || 4000;
const OPENAI_API_KEY = process.env.OPENAI_API_KEY;
const MONGODB_URI = process.env.MONGODB_URI || "mongodb://localhost:27017/whis-app";

// Razorpay Config
const RAZORPAY_KEY_ID = process.env.RAZORPAY_KEY_ID;
const RAZORPAY_KEY_SECRET = process.env.RAZORPAY_KEY_SECRET;

// --- INITIAL CHECKS ---
console.log("--- 🚀 STARTING SERVER WITH ENHANCED ANALYTICS ---");
if (!OPENAI_API_KEY) console.error("⚠️  MISSING: OPENAI_API_KEY");
if (!RAZORPAY_KEY_ID) console.error("⚠️  MISSING: RAZORPAY_KEY_ID");
if (!RAZORPAY_KEY_SECRET) console.error("⚠️  MISSING: RAZORPAY_KEY_SECRET");

const razorpay = new Razorpay({
  key_id: RAZORPAY_KEY_ID,
  key_secret: RAZORPAY_KEY_SECRET,
});

const upload = multer({ storage: multer.memoryStorage() });
const app = express();

// Trust Proxy for correct IP logging
app.set('trust proxy', true);

app.use(cors());
app.use(express.json({ limit: "50mb" }));

// --- 1. MongoDB Connection ---
mongoose
  .connect(MONGODB_URI)
  .then(() => console.log("✅ [DB] Connected to MongoDB"))
  .catch((err) => console.error("❌ [DB] Connection Failed:", err));

// --- 2. SCHEMAS ---

// A. Metric Schema (UPGRADED)
const metricSchema = new mongoose.Schema({
  date: { type: String, required: true }, // YYYY-MM-DD
  ip: { type: String, required: true },
  hits: { type: Number, default: 1 }, // Total raw hits
  
  // -- NEW ANALYTICS FIELDS --
  referrers: [String], // e.g. ["google.com", "instagram.com"]
  os: String,          // e.g. "Windows", "Mac", "Android"
  isMobile: Boolean,   // true/false
  
  // Specific Feature Counters
  stats: {
    chat: { type: Number, default: 0 },
    transcribe: { type: Number, default: 0 },
    payment: { type: Number, default: 0 }
  },
  
  userId: String, // Linked Google ID if logged in
  lastActive: { type: Date, default: Date.now }
});
// Compound index for fast upserts
metricSchema.index({ date: 1, ip: 1 }, { unique: true });

const Metric = mongoose.model("Metric", metricSchema);

// B. User Schema
const userSchema = new mongoose.Schema({
  googleId: { type: String, unique: true, required: true },
  email: { type: String, required: true },
  name: String,
  avatarUrl: String,
  phone: String,
  subscription: {
    status: { type: String, enum: ["active", "inactive", "past_due"], default: "inactive" },
    tier: { type: String, enum: ["free", "pro", "pro_plus"], default: "free" },
    cycle: { type: String, enum: ["monthly", "annual"], default: "monthly" },
    validUntil: Date
  },
  freeUsage: {
    count: { type: Number, default: 0 },
    lastDate: { type: String }
  },
  orders: [
    {
      orderId: String,          
      paymentId: String,        
      signature: String,        
      amount: Number,
      currency: String,
      date: Date,
      status: String,
      tier: String, 
      cycle: String,
      method: String,
      receipt: String,
      notes: Object
    }
  ],
  createdAt: { type: Date, default: Date.now },
  lastLogin: Date
});
const User = mongoose.model("User", userSchema);

// --------- 3. SMART TRAFFIC TRACKING MIDDLEWARE ---------
app.use(async (req, res, next) => {
  // 1. Filter out static noise (images/css/js) to save DB writes
  const isStatic = req.path.match(/\.(css|js|png|jpg|jpeg|ico|svg|woff|woff2)$/);
  
  if (!isStatic) {
    console.log(`📥 [REQ] ${req.method} ${req.path}`); // Lightweight console log
  }

  // If it's a static file, we skip the DB logic entirely to be fast
  if (isStatic) return next();

  try {
    // --- DATA EXTRACTION ---
    const today = new Date().toISOString().slice(0, 10);
    const ip = req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress;
    const ua = req.get('User-Agent') || "";
    const referrerHeader = req.get('Referrer') || req.get('Referer');
    const googleId = req.headers["x-google-id"] || req.body.googleId;

    // A. Parse OS & Device
    let os = "Unknown";
    let isMobile = /mobile|android|iphone|ipad|phone/i.test(ua);
    
    if (/windows/i.test(ua)) os = "Windows";
    else if (/macintosh|mac os/i.test(ua)) os = "Mac";
    else if (/linux/i.test(ua)) os = "Linux";
    else if (/android/i.test(ua)) os = "Android";
    else if (/ios|iphone|ipad/i.test(ua)) os = "iOS";

    // B. Parse Referrer (Extract domain only)
    let referrerDomain = null;
    if (referrerHeader) {
        try {
            const parsedUrl = new URL(referrerHeader);
            referrerDomain = parsedUrl.hostname; // e.g., "instagram.com"
        } catch (e) { /* ignore invalid urls */ }
    }

    // C. Determine Feature Usage
    const updates = { 
        $inc: { hits: 1 }, // Always increment total hits
        $set: { lastActive: new Date(), os: os, isMobile: isMobile },
        $addToSet: {} // Container for array updates
    };

    // Increment specific counters based on path
    if (req.path.includes("/chat-stream")) updates.$inc["stats.chat"] = 1;
    else if (req.path.includes("/transcribe")) updates.$inc["stats.transcribe"] = 1;
    else if (req.path.includes("/payment")) updates.$inc["stats.payment"] = 1;

    // Add referrer if it exists
    if (referrerDomain) {
        updates.$addToSet["referrers"] = referrerDomain;
    } else {
        delete updates.$addToSet; // Remove if empty to avoid mongo error
    }

    // Add UserID if found
    if (googleId) updates.$set["userId"] = googleId;

    // --- DB UPSERT ---
    await Metric.findOneAndUpdate(
      { date: today, ip: ip },
      updates,
      { upsert: true, new: true }
    );

  } catch (error) {
    console.error("⚠️ [ANALYTICS] Logging failed:", error.message);
  }

  next();
});

// Serve Static Files
app.use(express.static(__dirname));

// --------- Middleware (Auth Guard marker) ---------
app.use((req, res, next) => {
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
         console.log(`⚠️ [USAGE] Expired sub for ${user.email}`);
         user.subscription.status = 'inactive';
         user.subscription.tier = 'free';
         await user.save();
     } else {
         return { allowed: true, tier: user.subscription.tier };
     }
  }

  // Free Tier Logic
  if (user.freeUsage.lastDate !== today) {
    user.freeUsage.count = 0;
    user.freeUsage.lastDate = today;
  }

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
  console.log("👤 [AUTH] Login Request");
  try {
    const { token, tokens } = req.body;
    const idToken = token || (tokens && tokens.id_token);

    if (!idToken) return res.status(400).json({ error: "Missing ID Token" });

    const googleRes = await fetch(`https://oauth2.googleapis.com/tokeninfo?id_token=${idToken}`);
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
    console.error("❌ [AUTH] Error:", err);
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

    if (user.subscription.status === "active" && user.subscription.validUntil && new Date() > user.subscription.validUntil) {
      user.subscription.status = "inactive";
      user.subscription.tier = "free";
      await user.save();
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

// 3. CREATE RAZORPAY ORDER
app.post("/api/payment/create-order", async (req, res) => {
  console.log("💳 [PAYMENT] Creating Order...");
  try {
    const { googleId, tier, cycle } = req.body; 
    const user = await User.findOne({ googleId });
    if (!user) return res.status(404).json({ error: "User not found" });

    let amount = 0;
    if (tier === "pro") amount = (cycle === "annual") ? 5988.0 : 999.0;
    else if (tier === "pro_plus") amount = (cycle === "annual") ? 11988.0 : 2499.0;
    else return res.status(400).json({ error: "Invalid tier" });

    const amountInPaise = Math.round(amount * 100);
    const receiptId = `rcpt_${Date.now()}`;

    const options = {
      amount: amountInPaise,
      currency: "INR",
      receipt: receiptId,
      notes: { userId: googleId, tier: tier, cycle: cycle }
    };

    const order = await razorpay.orders.create(options);
    if (!order) throw new Error("Razorpay creation failed");

    user.orders.push({ 
      orderId: order.id, 
      amount: amount, 
      date: new Date(), 
      status: "created", 
      tier, cycle, receipt: receiptId, currency: "INR"
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
    console.error("❌ [PAYMENT] Order Error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// 4. VERIFY RAZORPAY PAYMENT
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
      } catch (e) { console.warn("Could not fetch payment details"); }

      user.subscription.status = "active";
      user.subscription.tier = order?.tier || "pro";
      const days = order?.cycle === "annual" ? 365 : 30;
      user.subscription.validUntil = new Date(Date.now() + days * 24 * 60 * 60 * 1000);

      if (order) {
        order.status = "paid";
        order.paymentId = razorpay_payment_id;
        order.signature = razorpay_signature;
      }
      
      await user.save();
      console.log(`✅ [PAYMENT] Verified for ${user.email}`);
      return res.json({ status: "success", success: true });
    } else {
      return res.status(400).json({ status: "failure", success: false, error: "Invalid Signature" });
    }
  } catch (err) {
    console.error("❌ [PAYMENT] Verify Error:", err);
    res.status(500).json({ error: "Verification failed" });
  }
});

// 5. STREAM CHAT
app.post("/api/chat-stream", async (req, res) => {
  const googleId = req.headers["x-google-id"];
   
  if (googleId) {
    const check = await checkAndIncrementUsage(googleId);
    if (!check.allowed) return res.status(403).json({ error: "Limit reached" });
  }

  const { conversationId, message } = req.body || {};
  if (!message || !message.role) return res.status(400).json({ error: "Invalid Body" });

  let convId = conversationId || `conv_${Date.now()}`;
  const history = conversations.get(convId) || [];

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

  history.push(newMessage);
  conversations.set(convId, history);

  res.setHeader("x-conversation-id", convId);
  res.setHeader("Content-Type", "text/plain; charset=utf-8");
  res.setHeader("Transfer-Encoding", "chunked");

  try {
    const openaiRes = await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      headers: { Authorization: `Bearer ${OPENAI_API_KEY}`, "Content-Type": "application/json" },
      body: JSON.stringify({ model: "gpt-4o-mini", messages: history, temperature: 0.6, stream: true })
    });

    if (!openaiRes.ok) {
        res.statusCode = 500;
        res.end(`OpenAI Error: ${openaiRes.status}`);
        return;
    }

    for await (const chunk of openaiRes.body) res.write(chunk);
    res.end();
  } catch (err) {
    console.error("❌ [AI] Stream Error:", err);
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
    console.error("❌ [TRANSCRIPTION] Error:", err.message);
    res.status(500).json({ error: "Transcription failed" });
  }
});

// --- CLEAN URL HANDLER (MUST BE LAST) ---
app.get('*', (req, res, next) => {
  if (req.path.startsWith('/api')) return next();
  if (req.path.includes('.')) return next();
  if (req.path === '/') return res.sendFile(path.join(__dirname, 'index.html'));
  
  res.sendFile(path.join(__dirname, req.path + '.html'), (err) => {
      if (err) next(); 
  });
});

app.listen(PORT, () => {
  console.log(`✅ Backend listening on http://localhost:${PORT}`);
});
