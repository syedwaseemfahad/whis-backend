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

// --- PRICING CONFIGURATION (Loaded from Env) ---
const PRICING = {
  pro: {
    monthly: parseFloat(process.env.PRO_PER_MONTH || 0), 
    annual_per_month: parseFloat(process.env.PRO_YEAR_PER_MONTH || 0),
    discount: parseFloat(process.env.PRO_DISCOUNT || 0)
  },
  pro_plus: {
    monthly: parseFloat(process.env.PROPLUS_PER_MONTH || 0), 
    annual_per_month: parseFloat(process.env.PROPLUS_YEAR_PER_MONTH || 0),
    discount: parseFloat(process.env.PROPLUS_DISCOUNT || 0)
  }
};

// --- INITIAL CHECKS ---
console.log("--- 🚀 STARTING SERVER ---");
if (!OPENAI_API_KEY) console.error("⚠️  MISSING: OPENAI_API_KEY");
if (!RAZORPAY_KEY_ID) console.error("⚠️  MISSING: RAZORPAY_KEY_ID");

const razorpay = new Razorpay({
  key_id: RAZORPAY_KEY_ID,
  key_secret: RAZORPAY_KEY_SECRET,
});

const upload = multer({ 
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 } // Increased limit slightly for system audio
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
      orderId: String, paymentId: String, signature: String, amount: Number,
      currency: String, date: Date, status: String, tier: String, 
      cycle: String, method: String, receipt: String, notes: Object
    }
  ],
  createdAt: { type: Date, default: Date.now },
  lastLogin: Date
});
const User = mongoose.model("User", userSchema);

// NOTE: Conversation persistence removed as requested.

// --------- 3. TRAFFIC TRACKING MIDDLEWARE ---------
app.use((req, res, next) => {
  const isStatic = req.path.match(/\.(css|js|png|jpg|jpeg|ico|svg|woff|woff2)$/);
  if (!isStatic) console.log(`📥 [REQ] ${req.method} ${req.path}`);
  if (isStatic) return next();

  try {
    const today = new Date().toISOString().slice(0, 10);
    const ip = req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress;
    
    // Non-blocking metric update
    Metric.findOneAndUpdate(
      { date: today, ip: ip },
      { $inc: { hits: 1 }, $set: { lastActive: new Date() } },
      { upsert: true, new: true }
    ).catch(() => {});
  } catch (error) {}
  next();
});

app.use(express.static(__dirname));

// --- HELPER: Usage Check ---
async function checkAndIncrementUsage(googleId) {
  const today = new Date().toISOString().slice(0, 10);
  const user = await User.findOne({ googleId });
   
  if (!user) return { allowed: false, error: "User not found" };

  if (user.subscription.status === 'active' && ['pro', 'pro_plus'].includes(user.subscription.tier)) {
     if (user.subscription.validUntil && new Date() > user.subscription.validUntil) {
         user.subscription.status = 'inactive';
         user.subscription.tier = 'free';
         await user.save();
     } else {
         return { allowed: true, tier: user.subscription.tier };
     }
  }

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

app.get("/ping", (req, res) => res.send("pong"));

// 0. CONFIG ROUTE - New! Sends Pricing + Client ID to UI so UI needs no .env
app.get("/api/config", (req, res) => {
    res.json({
        pricing: PRICING,
        googleClientId: process.env.GOOGLE_CLIENT_ID
    });
});

// 1. AUTH
app.post("/api/auth/google", async (req, res) => {
  try {
    // We expect the electron main process to send the full profile and tokens
    const { user: userInput, tokens } = req.body; 
    
    if (!userInput || !userInput.id) return res.status(400).json({ error: "Invalid User Data" });

    const googleId = userInput.id;
    const email = userInput.email;
    const name = userInput.name;
    const avatarUrl = userInput.picture;

    const user = await User.findOneAndUpdate(
      { googleId },
      {
        email, name, avatarUrl, lastLogin: new Date(),
        $setOnInsert: {
          "subscription.status": "inactive", "subscription.tier": "free",
          "freeUsage.count": 0, "freeUsage.lastDate": new Date().toISOString().slice(0, 10)
        }
      },
      { new: true, upsert: true }
    );
    res.json({ success: true, user });
  } catch (err) {
    console.error("Auth DB Error:", err);
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

// 3. PAYMENT ROUTES
app.post("/api/payment/create-order", async (req, res) => {
  try {
    const { googleId, tier, cycle } = req.body; 
    const user = await User.findOne({ googleId });
    if (!user) return res.status(404).json({ error: "User not found" });

    let priceInfo;
    let basePrice = 0.00;
    
    if (tier === "pro") priceInfo = PRICING.pro;
    else if (tier === "pro_plus") priceInfo = PRICING.pro_plus;
    else return res.status(400).json({ error: "Invalid tier" });

    basePrice = (cycle === "annual") ? (priceInfo.annual_per_month * 12) : priceInfo.monthly;
    const discountAmount = (basePrice * priceInfo.discount) / 100;
    let finalAmount = basePrice - discountAmount;
    
    // Upgrade Logic
    let isUpgrade = false;
    let oldPlanCredit = 0.00;
    
    if (user.subscription.status === 'active' && user.subscription.tier === 'pro' && tier === 'pro_plus') {
        isUpgrade = true;
        let oldBasePrice = (user.subscription.cycle === 'monthly') ? PRICING.pro.monthly : (PRICING.pro.annual_per_month * 12);
        const oldDiscountAmount = (oldBasePrice * PRICING.pro.discount) / 100;
        oldPlanCredit = oldBasePrice - oldDiscountAmount;
        finalAmount = finalAmount - oldPlanCredit;
    }

    if (finalAmount < 0) finalAmount = 0;
    finalAmount = Math.floor(finalAmount); 
    const amountInPaise = finalAmount * 100; 

    const receiptId = `rcpt_${Date.now()}`;
    const options = { 
        amount: amountInPaise, currency: "INR", receipt: receiptId, 
        notes: { userId: googleId, tier, cycle } 
    };

    const order = await razorpay.orders.create(options);
    user.orders.push({ 
        orderId: order.id, amount: finalAmount, date: new Date(), 
        status: "created", tier, cycle, receipt: receiptId, currency: "INR" 
    });
    await user.save();

    res.json({ 
        order_id: order.id, amount: amountInPaise, currency: "INR", 
        key_id: RAZORPAY_KEY_ID, user_name: user.name, user_email: user.email, 
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
      
      const days = order?.cycle === "annual" ? 365 : 30;
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

// 5. STREAM CHAT (Stateless)
app.post("/api/chat-stream", async (req, res) => {
  const googleId = req.headers["x-google-id"];
   
  if (googleId) {
    const check = await checkAndIncrementUsage(googleId);
    if (!check.allowed) return res.status(403).json({ error: "Limit reached" });
  }

  const { conversationId, message } = req.body || {};
  if (!message || !message.role) return res.status(400).json({ error: "Invalid Body" });

  const convId = conversationId || `conv_${Date.now()}`;

  // Stateless Context Construction
  let openAiMessages = [];
  
  // Format message content (text + optional image)
  let contentPayload = message.content;
  if (message.screenshot) {
    let sc = message.screenshot.startsWith("data:image") ? message.screenshot : `data:image/png;base64,${message.screenshot}`;
    contentPayload = [
        { type: "text", text: message.content || "Analyze this." },
        { type: "image_url", image_url: { url: sc } }
    ];
  }
  
  openAiMessages.push({ role: message.role, content: contentPayload });

  // System Prompt for Context
  openAiMessages.unshift({ 
      role: "system", 
      content: "You are Whis, a helpful assistant overlay. Be concise, direct, and helpful. You are helping the user during a live call or meeting." 
  });

  try {
    res.setHeader("x-conversation-id", convId);
    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    res.setHeader("Transfer-Encoding", "chunked");

    const openaiRes = await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      headers: { Authorization: `Bearer ${OPENAI_API_KEY}`, "Content-Type": "application/json" },
      body: JSON.stringify({ model: "gpt-4o-mini", messages: openAiMessages, temperature: 0.6, stream: true })
    });

    if (!openaiRes.ok) {
        res.statusCode = 500;
        res.end(`OpenAI Error: ${openaiRes.status}`);
        return;
    }

    const decoder = new TextDecoder();
    for await (const chunk of openaiRes.body) {
        const text = decoder.decode(chunk, { stream: true });
        const lines = text.split('\n');
        for (const line of lines) {
            if (line.startsWith('data: ') && line !== 'data: [DONE]') {
                try {
                    const json = JSON.parse(line.replace('data: ', ''));
                    const content = json.choices[0]?.delta?.content || "";
                    if (content) res.write(`data: ${JSON.stringify({choices:[{delta:{content:content}}]})}\n\n`);
                } catch (e) { }
            }
        }
    }
    res.write("data: [DONE]\n\n");
    res.end();
  } catch (err) {
    console.error("❌ [AI] Stream Error:", err);
    if (!res.headersSent) res.status(500).end("Internal Stream Error");
  }
});

// 6. TRANSCRIPTION
app.post("/api/transcribe", upload.single("file"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: "Missing file" });
    
    // Check mime type, default to webm if missing (typical for electron media recorder)
    const mime = req.file.mimetype || "audio/wav";
    const filename = req.file.originalname || "audio.wav";
    
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

// Fallback for SPA/Electron routing
app.get('*', (req, res, next) => {
  if (req.path.startsWith('/api')) return next();
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => {
  console.log(`✅ Backend listening on http://localhost:${PORT}`);
});
