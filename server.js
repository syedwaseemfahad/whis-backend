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

// --- PRICING CONFIGURATION (STRICTLY FROM ENV) ---
// [IMPORTANT]: No fallback values. Returns NaN if env is missing.
const PRICING = {
  pro: {
    monthly: parseFloat(process.env.PRO_PER_MONTH), 
    annual_per_month: parseFloat(process.env.PRO_YEAR_PER_MONTH),
    discount: parseFloat(process.env.PRO_DISCOUNT || 0)
  },
  pro_plus: {
    monthly: parseFloat(process.env.PROPLUS_PER_MONTH), 
    annual_per_month: parseFloat(process.env.PROPLUS_YEAR_PER_MONTH),
    discount: parseFloat(process.env.PROPLUS_DISCOUNT || 0)
  }
};

// --- INITIAL CHECKS ---
console.log("--- 🚀 STARTING SERVER ---");
console.log("Pricing Loaded from ENV:", JSON.stringify(PRICING, null, 2)); // Debug Log

if (!OPENAI_API_KEY) console.error("⚠️  MISSING: OPENAI_API_KEY");
if (!RAZORPAY_KEY_ID) console.error("⚠️  MISSING: RAZORPAY_KEY_ID");
if (isNaN(PRICING.pro.monthly)) console.error("⚠️  MISSING PRICING ENV VARIABLES");

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

// Serve Static Files
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

// 0. CONFIG ROUTE - Sends Pricing to UI
app.get("/api/config/pricing", (req, res) => {
    res.json(PRICING);
});

// 1. AUTH
app.post("/api/auth/google", async (req, res) => {
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
          "subscription.status": "inactive", "subscription.tier": "free",
          "freeUsage.count": 0, "freeUsage.lastDate": new Date().toISOString().slice(0, 10)
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

    console.log(`[Order] User: ${googleId}, Plan: ${tier}, Cycle: ${cycle}`);

    // --- 1. Calculate TARGET Plan Price ---
    let priceInfo;
    let basePrice = 0.00;
    
    if (tier === "pro") {
        priceInfo = PRICING.pro;
        basePrice = (cycle === "annual") ? (priceInfo.annual_per_month * 12) : priceInfo.monthly;
    } else if (tier === "pro_plus") {
        priceInfo = PRICING.pro_plus;
        basePrice = (cycle === "annual") ? (priceInfo.annual_per_month * 12) : priceInfo.monthly;
    } else {
        return res.status(400).json({ error: "Invalid tier" });
    }

    // Apply Discount
    const discountAmount = (basePrice * priceInfo.discount) / 100;
    let finalAmount = basePrice - discountAmount;
    
    console.log(`[Calc] Base: ${basePrice}, Discounted: ${finalAmount}`);

    // --- 2. Calculate UPGRADE Diff ---
    // Rule: New Cost - Old Cost (Current Active)
    let isUpgrade = false;
    
    if (user.subscription.status === 'active' && 
        user.subscription.tier === 'pro' && 
        tier === 'pro_plus') {
        
        isUpgrade = true;
        
        // Find Cost of User's CURRENT active plan
        // This relies on PRICING env vars matching what they originally paid
        let oldPlanCost = 0.00;
        
        if (user.subscription.cycle === 'monthly') {
            oldPlanCost = PRICING.pro.monthly;
        } else {
            oldPlanCost = PRICING.pro.annual_per_month * 12;
        }

        console.log(`[Upgrade] Subtracting Old Cost: ${oldPlanCost}`);
        finalAmount = finalAmount - oldPlanCost;
    }

    // Precision Check
    if (finalAmount < 0) finalAmount = 0;

    // Round to 2 decimals, convert to paise
    finalAmount = parseFloat(finalAmount.toFixed(2));
    const amountInPaise = Math.round(finalAmount * 100); 

    console.log(`[Final] Amount to Charge: ${finalAmount}`);

    const receiptId = `rcpt_${Date.now()}`;
    const options = { 
        amount: amountInPaise, 
        currency: "INR", 
        receipt: receiptId, 
        notes: { userId: googleId, tier, cycle, isUpgrade: isUpgrade } 
    };

    const order = await razorpay.orders.create(options);
    user.orders.push({ 
        orderId: order.id, 
        amount: finalAmount, 
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
      // Update cycle so future upgrades are calculated correctly
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

// 5. STREAM CHAT
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

    const history = conversation.messages.map(m => ({ role: m.role, content: m.content }));

    res.setHeader("x-conversation-id", convId);
    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    res.setHeader("Transfer-Encoding", "chunked");

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

// 6. TRANSCRIPTION
app.post("/api/transcribe", upload.single("file"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: "Missing file or file too large (Max 5MB)" });
    
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

app.get('*', (req, res, next) => {
  if (req.path.startsWith('/api')) return next();
  if (req.path.includes('.')) return next();
  if (req.path === '/') return res.sendFile(path.join(__dirname, 'index.html'));
  res.sendFile(path.join(__dirname, req.path + '.html'), (err) => { if (err) next(); });
});

app.listen(PORT, () => {
  console.log(`✅ Backend listening on http://localhost:${PORT}`);
});
