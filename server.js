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
const OPENAI_API_KEY = process.env.OPENAI_API_KEY;
const MONGODB_URI = process.env.MONGODB_URI || "mongodb://localhost:27017/whis-app";
const RAZORPAY_KEY_ID = process.env.RAZORPAY_KEY_ID;
const RAZORPAY_KEY_SECRET = process.env.RAZORPAY_KEY_SECRET;

// Client Configuration (Publicly shareable via API)
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET; // Server-side only!
const WEBSITE_PRICING_URL = process.env.WEBSITE_PRICING_URL || "http://localhost:8000/pricing.html";

// --- PRICING CONFIGURATION ---
const PRICING = {
  pro: {
    monthly: parseFloat(process.env.PRO_PER_MONTH || 1999), 
    annual_per_month: parseFloat(process.env.PRO_YEAR_PER_MONTH || 1699),
    discount: parseFloat(process.env.PRO_DISCOUNT || 0)
  },
  pro_plus: {
    monthly: parseFloat(process.env.PROPLUS_PER_MONTH || 2999), 
    annual_per_month: parseFloat(process.env.PROPLUS_YEAR_PER_MONTH || 2499),
    discount: parseFloat(process.env.PROPLUS_DISCOUNT || 0)
  }
};

// --- INITIAL CHECKS ---
console.log("--- 🚀 STARTING SERVER ---");
if (!OPENAI_API_KEY) console.error("⚠️  MISSING: OPENAI_API_KEY");
if (!GOOGLE_CLIENT_ID) console.error("⚠️  MISSING: GOOGLE_CLIENT_ID");
if (!GOOGLE_CLIENT_SECRET) console.error("⚠️  MISSING: GOOGLE_CLIENT_SECRET");

const razorpay = new Razorpay({
  key_id: RAZORPAY_KEY_ID,
  key_secret: RAZORPAY_KEY_SECRET,
});

const upload = multer({ 
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 } 
});

const app = express();
app.set('trust proxy', true);
app.use(cors());
app.use(express.json({ limit: "50mb" })); 

// --- 1. MongoDB Connection ---
mongoose.connect(MONGODB_URI)
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
  stats: { chat: { type: Number, default: 0 }, transcribe: { type: Number, default: 0 }, payment: { type: Number, default: 0 } },
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
  subscription: {
    status: { type: String, enum: ["active", "inactive", "past_due"], default: "inactive" },
    tier: { type: String, enum: ["free", "pro", "pro_plus"], default: "free" },
    cycle: { type: String, enum: ["monthly", "annual"], default: "monthly" },
    validUntil: Date
  },
  freeUsage: { count: { type: Number, default: 0 }, lastDate: { type: String } },
  orders: [ { orderId: String, paymentId: String, signature: String, amount: Number, currency: String, date: Date, status: String, tier: String, cycle: String, method: String, receipt: String } ],
  createdAt: { type: Date, default: Date.now },
  lastLogin: Date
});
const User = mongoose.model("User", userSchema);

const conversationSchema = new mongoose.Schema({
  conversationId: { type: String, required: true, unique: true, index: true },
  userId: String,
  messages: [ { role: { type: String }, content: mongoose.Schema.Types.Mixed, timestamp: { type: Date, default: Date.now } } ],
  updatedAt: { type: Date, default: Date.now }
});
conversationSchema.index({ updatedAt: 1 }, { expireAfterSeconds: 86400 }); 
const Conversation = mongoose.model("Conversation", conversationSchema);

// --------- 3. MIDDLEWARE ---------
app.use((req, res, next) => {
  const isStatic = req.path.match(/\.(css|js|png|jpg|jpeg|ico|svg|woff|woff2)$/);
  if (!isStatic) console.log(`📥 [REQ] ${req.method} ${req.path}`);
  if (isStatic) return next();

  try {
    const today = new Date().toISOString().slice(0, 10);
    const ip = req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress;
    const ua = req.get('User-Agent') || "";
    const googleId = req.headers["x-google-id"] || req.body.googleId;
    
    // Simple updates
    const updates = { $inc: { hits: 1 }, $set: { lastActive: new Date() } };
    if (googleId) updates.$set["userId"] = googleId;

    Metric.findOneAndUpdate({ date: today, ip: ip }, updates, { upsert: true, new: true }).catch(() => {});
  } catch (e) {}
  next();
});

// --- HELPER: Usage Check ---
async function checkAndIncrementUsage(googleId) {
  const today = new Date().toISOString().slice(0, 10);
  const user = await User.findOne({ googleId });
  if (!user) return { allowed: false, error: "User not found" };

  if (user.subscription.status === 'active' && ['pro', 'pro_plus'].includes(user.subscription.tier)) {
     if (user.subscription.validUntil && new Date() > user.subscription.validUntil) {
         user.subscription.status = 'inactive'; user.subscription.tier = 'free';
         await user.save();
     } else {
         return { allowed: true, tier: user.subscription.tier };
     }
  }

  if (user.freeUsage.lastDate !== today) { user.freeUsage.count = 0; user.freeUsage.lastDate = today; }
  if (user.freeUsage.count >= 10) return { allowed: false, error: "Daily limit reached" };

  user.freeUsage.count += 1;
  await user.save();
  return { allowed: true, tier: 'free' };
}

// ================= ROUTES =================

app.get("/ping", (req, res) => res.send("pong"));

// CONFIG ROUTE (Requirement: App fetches ID/Pricing from here)
app.get("/api/config", (req, res) => {
    res.json({ googleClientId: GOOGLE_CLIENT_ID, pricingUrl: WEBSITE_PRICING_URL });
});

// AUTH ROUTE (Secure Code Exchange)
app.post("/api/auth/google", async (req, res) => {
  try {
    const { code, redirect_uri } = req.body;
    let userData;

    if (code) {
        // Exchange Code for Token using Secret
        const params = new URLSearchParams();
        params.append("code", code);
        params.append("client_id", GOOGLE_CLIENT_ID);
        params.append("client_secret", GOOGLE_CLIENT_SECRET);
        params.append("redirect_uri", redirect_uri);
        params.append("grant_type", "authorization_code");

        const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
            method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: params
        });
        if(!tokenRes.ok) return res.status(401).json({ error: "Token Exchange Failed" });
        const tokens = await tokenRes.json();

        // Get Profile
        const profileRes = await fetch("https://www.googleapis.com/oauth2/v2/userinfo", {
            headers: { Authorization: `Bearer ${tokens.access_token}` }
        });
        userData = await profileRes.json();
    } else {
        return res.status(400).json({ error: "Missing code" });
    }

    // Upsert User
    const user = await User.findOneAndUpdate(
      { googleId: userData.id },
      {
        email: userData.email, name: userData.name, avatarUrl: userData.picture, lastLogin: new Date(),
        $setOnInsert: { "subscription.status": "inactive", "subscription.tier": "free", "freeUsage.count": 0, "freeUsage.lastDate": new Date().toISOString().slice(0, 10) }
      },
      { new: true, upsert: true }
    );
    res.json({ success: true, user });

  } catch (err) {
    console.error("Auth Error:", err);
    res.status(500).json({ error: "Internal Error" });
  }
});

app.get("/api/user/status", async (req, res) => {
  try {
    const googleId = req.headers["x-google-id"];
    const user = await User.findOne({ googleId });
    if (!user) return res.json({ active: false });
    res.json({
      active: user.subscription.status === "active",
      tier: user.subscription.tier,
      validUntil: user.subscription.validUntil,
      freeUsage: user.freeUsage
    });
  } catch (err) { res.status(500).json({ error: "Error" }); }
});

// PAYMENT - CREATE ORDER
app.post("/api/payment/create-order", async (req, res) => {
  try {
    const { googleId, tier, cycle } = req.body; 
    const user = await User.findOne({ googleId });
    if (!user) return res.status(404).json({ error: "User not found" });

    // Calculate Price
    const priceInfo = PRICING[tier];
    if(!priceInfo) return res.status(400).json({ error: "Invalid tier" });

    let basePrice = cycle === "annual" ? (priceInfo.annual_per_month * 12) : priceInfo.monthly;
    let finalAmount = basePrice - ((basePrice * priceInfo.discount) / 100);
    
    finalAmount = Math.floor(finalAmount);
    const amountInPaise = finalAmount * 100; 

    const receiptId = `rcpt_${Date.now()}`;
    const order = await razorpay.orders.create({ amount: amountInPaise, currency: "INR", receipt: receiptId });
    
    user.orders.push({ orderId: order.id, amount: finalAmount, date: new Date(), status: "created", tier, cycle, receipt: receiptId });
    await user.save();

    res.json({ order_id: order.id, amount: amountInPaise, currency: "INR", key_id: RAZORPAY_KEY_ID });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// PAYMENT - VERIFY
app.post("/api/payment/verify", async (req, res) => {
  try {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body;
    const body = razorpay_order_id + "|" + razorpay_payment_id;
    const expectedSignature = crypto.createHmac("sha256", RAZORPAY_KEY_SECRET).update(body.toString()).digest("hex");

    if (expectedSignature === razorpay_signature) {
      const user = await User.findOne({ "orders.orderId": razorpay_order_id });
      if (!user) return res.status(404).json({ error: "Order not found" });
      
      const order = user.orders.find((o) => o.orderId === razorpay_order_id);
      user.subscription.status = "active";
      user.subscription.tier = order?.tier || "pro";
      user.subscription.cycle = order?.cycle || "monthly";
      const days = order?.cycle === "annual" ? 365 : 30;
      user.subscription.validUntil = new Date(Date.now() + days * 24 * 60 * 60 * 1000);
      
      if (order) { order.status = "paid"; order.paymentId = razorpay_payment_id; }
      await user.save();
      return res.json({ success: true });
    } else {
      return res.status(400).json({ success: false, error: "Invalid Signature" });
    }
  } catch (err) { res.status(500).json({ error: "Verification failed" }); }
});

// CHAT STREAM (Vision Enabled)
app.post("/api/chat-stream", async (req, res) => {
  const googleId = req.headers["x-google-id"];
  if (googleId) {
    const check = await checkAndIncrementUsage(googleId);
    if (!check.allowed) return res.status(403).json({ error: "Limit reached" });
  }

  const { conversationId, message } = req.body || {};
  if (!message || !message.role) return res.status(400).json({ error: "Invalid Body" });

  const convId = conversationId || `conv_${Date.now()}`;
  let newMessage = { role: message.role, content: message.content };
  
  // Vision Handling
  if (message.screenshot) {
    let sc = message.screenshot.startsWith("data:image") ? message.screenshot : `data:image/jpeg;base64,${message.screenshot}`;
    newMessage = { 
        role: message.role, 
        content: [ { type: "text", text: message.content || "Analyze image." }, { type: "image_url", image_url: { url: sc } } ]
    };
  }

  try {
    // Save User Msg
    await Conversation.findOneAndUpdate({ conversationId: convId }, { $push: { messages: newMessage }, $set: { updatedAt: new Date(), userId: googleId }}, { new: true, upsert: true });

    // OpenAI Call
    const conv = await Conversation.findOne({ conversationId: convId });
    const history = conv.messages.map(m => ({ role: m.role, content: m.content }));

    res.setHeader("x-conversation-id", convId);
    res.setHeader("Content-Type", "text/plain");

    const openaiRes = await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      headers: { Authorization: `Bearer ${OPENAI_API_KEY}`, "Content-Type": "application/json" },
      body: JSON.stringify({ model: "gpt-4o", messages: history, stream: true })
    });

    const decoder = new TextDecoder();
    let fullAiResponse = "";

    for await (const chunk of openaiRes.body) {
        const text = decoder.decode(chunk, { stream: true });
        const lines = text.split('\n');
        for (const line of lines) {
            if (line.startsWith('data: ') && line !== 'data: [DONE]') {
                try {
                    const content = JSON.parse(line.replace('data: ', '')).choices[0]?.delta?.content || "";
                    fullAiResponse += content;
                    res.write(content);
                } catch (e) { }
            }
        }
    }
    
    if (fullAiResponse) {
        await Conversation.updateOne({ conversationId: convId }, { $push: { messages: { role: "assistant", content: fullAiResponse } } });
    }
    res.end();

  } catch (err) { res.status(500).end("Stream Error"); }
});

// TRANSCRIPTION
app.post("/api/transcribe", upload.single("file"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: "No file" });
    const formData = new FormData();
    formData.append("file", new Blob([req.file.buffer], { type: req.file.mimetype }), "audio.wav");
    formData.append("model", "whisper-1"); 

    const openaiRes = await fetch("https://api.openai.com/v1/audio/transcriptions", {
        method: "POST", headers: { Authorization: `Bearer ${OPENAI_API_KEY}` }, body: formData
    });
    const data = await openaiRes.json();
    res.json({ text: data.text || "" });
  } catch (err) { res.status(500).json({ error: "Transcription failed" }); }
});

app.listen(PORT, () => console.log(`✅ Backend running on port ${PORT}`));
