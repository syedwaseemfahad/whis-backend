require("dotenv").config();

const express = require("express");
const cors = require("cors");
const multer = require("multer");
const mongoose = require("mongoose");
const Razorpay = require("razorpay");
const crypto = require("crypto");
const path = require("path");

// --- CONFIGURATION ---
const PORT = process.env.PORT || 4000;
const OPENAI_API_KEY = process.env.OPENAI_API_KEY;
const MONGODB_URI = process.env.MONGODB_URI || "mongodb://localhost:27017/whis-app";

// Razorpay Config
const RAZORPAY_KEY_ID = process.env.RAZORPAY_KEY_ID;
const RAZORPAY_KEY_SECRET = process.env.RAZORPAY_KEY_SECRET;

// --- INITIAL CHECKS ---
console.log("--- 🚀 STARTING SERVER ---");
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

// A. Metric Schema
const metricSchema = new mongoose.Schema({
  date: { type: String, required: true },
  ip: { type: String, required: true },
  hits: { type: Number, default: 1 },
  userId: String,
  userAgent: String,
  routesAccessed: [{ type: String }],
  lastActive: { type: Date, default: Date.now }
});
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

// --------- 3. GLOBAL LOGGING & TRAFFIC TRACKING ---------
app.use(async (req, res, next) => {
  // 1. Filter out noise (images/css/js)
  const isStatic = req.path.match(/\.(css|js|png|jpg|jpeg|ico|svg|woff|woff2)$/);
  
  if (!isStatic) {
    // 2. Log the Incoming Request
    console.log(`📥 [REQ] ${req.method} ${req.path} | IP: ${req.ip}`);
  }

  // 3. Traffic Analytics Logic
  if (req.path.match(/\.(css|js|png|jpg|jpeg|ico|svg|woff|woff2)$/)) {
    return next(); // Skip analytics for static files
  }

  try {
    const today = new Date().toISOString().slice(0, 10);
    const ip = req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress;
    const userAgent = req.get('User-Agent');
    const googleId = req.headers["x-google-id"] || req.body.googleId;

    await Metric.findOneAndUpdate(
      { date: today, ip: ip },
      { 
        $inc: { hits: 1 },
        $addToSet: { routesAccessed: req.path },
        $set: { 
          lastActive: new Date(),
          userAgent: userAgent,
          ...(googleId && { userId: googleId })
        }
      },
      { upsert: true, new: true }
    );
    if (!isStatic) console.log(`📊 [TRAFFIC] Logged hit for IP: ${ip}`);
  } catch (error) {
    console.error("⚠️ [TRAFFIC] Logging failed:", error.message);
  }

  next();
});

// Serve Static Files
app.use(express.static(__dirname));

// --------- Middleware (Auth Guard) ---------
app.use((req, res, next) => {
  if (req.path.startsWith("/api/")) {
    // Just a marker for API requests
  }
  next();
});

const conversations = new Map();

// --- Helper: Usage Check ---
async function checkAndIncrementUsage(googleId) {
  console.log(`🔎 [USAGE] Checking limits for User: ${googleId}`);
  const today = new Date().toISOString().slice(0, 10);
  const user = await User.findOne({ googleId });
   
  if (!user) {
    console.error(`❌ [USAGE] User not found: ${googleId}`);
    return { allowed: false, error: "User not found" };
  }

  // Check Paid Status
  if (user.subscription.status === 'active' && ['pro', 'pro_plus'].includes(user.subscription.tier)) {
     if (user.subscription.validUntil && new Date() > user.subscription.validUntil) {
         console.log(`⚠️ [USAGE] Subscription EXPIRED for ${user.email}. Downgrading.`);
         user.subscription.status = 'inactive';
         user.subscription.tier = 'free';
         await user.save();
     } else {
         console.log(`✅ [USAGE] PRO Access Granted: ${user.subscription.tier}`);
         return { allowed: true, tier: user.subscription.tier };
     }
  }

  // Free Tier Logic
  if (user.freeUsage.lastDate !== today) {
    console.log(`🔄 [USAGE] Resetting daily free count for ${user.email}`);
    user.freeUsage.count = 0;
    user.freeUsage.lastDate = today;
  }

  // Limit: 10
  if (user.freeUsage.count >= 10) {
    console.warn(`⛔ [USAGE] Daily limit reached for ${user.email} (Count: ${user.freeUsage.count})`);
    return { allowed: false, error: "Daily limit reached" };
  }

  user.freeUsage.count += 1;
  await user.save();
  console.log(`✅ [USAGE] Free usage incremented. Count: ${user.freeUsage.count}/10`);
  return { allowed: true, tier: 'free', remaining: 10 - user.freeUsage.count };
}

// ================= ROUTES =================

// 1. AUTH
app.post("/api/auth/google", async (req, res) => {
  console.log("👤 [AUTH] Google Login Attempt...");
  try {
    const { token, tokens } = req.body;
    const idToken = token || (tokens && tokens.id_token);

    if (!idToken) {
        console.error("❌ [AUTH] Missing ID Token");
        return res.status(400).json({ error: "Missing ID Token" });
    }

    const googleRes = await fetch(`https://oauth2.googleapis.com/tokeninfo?id_token=${idToken}`);
    if (!googleRes.ok) {
        console.error("❌ [AUTH] Invalid Google Token");
        return res.status(401).json({ error: "Invalid Google Token" });
    }

    const payload = await googleRes.json();
    const { sub: googleId, email, name, picture: avatarUrl } = payload;

    console.log(`👤 [AUTH] Verified: ${email} (${name})`);

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
    console.error("❌ [AUTH] DB/Server Error:", err);
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

    // 1. Check Subscription Expiry
    if (user.subscription.status === "active" && user.subscription.validUntil && new Date() > user.subscription.validUntil) {
      console.log(`📉 [STATUS] Subscription expired naturally for ${user.email}`);
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
    console.error("❌ [STATUS] Error:", err);
    res.status(500).json({ error: "Failed to check status" });
  }
});

// 3. CREATE RAZORPAY ORDER
app.post("/api/payment/create-order", async (req, res) => {
  console.log("💳 [PAYMENT] Create Order Request...");
  try {
    const { googleId, tier, cycle } = req.body; 
    console.log(`💳 [PAYMENT] Tier: ${tier}, Cycle: ${cycle}, User: ${googleId}`);

    const user = await User.findOne({ googleId });
    if (!user) return res.status(404).json({ error: "User not found" });

    // --- PRICING LOGIC ---
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
    if (!order) throw new Error("Razorpay returned null order");

    console.log(`💳 [PAYMENT] Order Created! ID: ${order.id}`);

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
    console.error("❌ [PAYMENT] Create Order Failed:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// 4. VERIFY RAZORPAY PAYMENT
app.post("/api/payment/verify", async (req, res) => {
  console.log("💳 [PAYMENT] Verifying Payment...");
  try {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body;

    const body = razorpay_order_id + "|" + razorpay_payment_id;
    const expectedSignature = crypto
      .createHmac("sha256", RAZORPAY_KEY_SECRET)
      .update(body.toString())
      .digest("hex");

    if (expectedSignature === razorpay_signature) {
      console.log("✅ [PAYMENT] Signature Matches. Payment Valid.");
      const user = await User.findOne({ "orders.orderId": razorpay_order_id });
      
      if (!user) {
        console.error("❌ [PAYMENT] User not found for order:", razorpay_order_id);
        return res.status(404).json({ error: "Order not found attached to user" });
      }

      const order = user.orders.find((o) => o.orderId === razorpay_order_id);
      
      // Fetch details from Razorpay to get method/phone
      try {
        const paymentDetails = await razorpay.payments.fetch(razorpay_payment_id);
        if (order) order.method = paymentDetails.method;
        if (paymentDetails.contact && !user.phone) user.phone = paymentDetails.contact;
      } catch (e) { console.warn("⚠️ [PAYMENT] Could not fetch details from Razorpay API"); }

      // ACTIVATE SUB
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
      console.log(`🎉 [PAYMENT] User ${user.email} upgraded to ${user.subscription.tier}`);
      return res.json({ status: "success", success: true });

    } else {
      console.error("❌ [PAYMENT] Invalid Signature!");
      return res.status(400).json({ status: "failure", success: false, error: "Invalid Signature" });
    }
  } catch (err) {
    console.error("❌ [PAYMENT] Verification Error:", err);
    res.status(500).json({ error: "Verification failed" });
  }
});

// 5. STREAM CHAT
app.post("/api/chat-stream", async (req, res) => {
  const googleId = req.headers["x-google-id"];
  console.log("🤖 [AI] Chat Stream Request initiated");

  if (googleId) {
    const check = await checkAndIncrementUsage(googleId);
    if (!check.allowed) {
        console.warn(`⛔ [AI] Blocked request for ${googleId}: Limit reached`);
        return res.status(403).json({ error: "Daily limit reached. Please upgrade to Pro." });
    }
  }

  const { conversationId, message } = req.body || {};
  
  if (!message || !message.role) {
    console.error("❌ [AI] Invalid Body Format");
    return res.status(400).json({ error: "Invalid Body" });
  }

  let convId = conversationId || `conv_${Date.now()}`;
  const history = conversations.get(convId) || [];

  // Prepare OpenAI Message
  let newMessage;
  if (message.screenshot) {
    console.log("📸 [AI] Processing Screenshot...");
    let screenshot = message.screenshot;
    if (!screenshot.startsWith("data:image")) screenshot = `data:image/png;base64,${screenshot}`;
    
    newMessage = { 
        role: message.role, 
        content: [
            { type: "text", text: message.content || "Analyze this screenshot contextually." },
            { type: "image_url", image_url: { url: screenshot } }
        ]
    };
  } else {
    newMessage = { role: message.role, content: message.content };
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
      console.error(`❌ [AI] OpenAI API Error: ${openaiRes.status}`, errText);
      res.statusCode = 500;
      res.end(`OpenAI Error: ${openaiRes.status}`);
      return;
    }

    console.log("🌊 [AI] Streaming response...");
    for await (const chunk of openaiRes.body) {
      res.write(chunk);
    }
    console.log("✅ [AI] Stream finished.");
    res.end();
  } catch (err) {
    console.error("❌ [AI] Internal Stream Error:", err);
    res.statusCode = 500;
    res.end("Internal Stream Error");
  }
});

// 6. TRANSCRIPTION
app.post("/api/transcribe", upload.single("file"), async (req, res) => {
  console.log("🎙️ [TRANSCRIPTION] Received Audio File");
  try {
    if (!req.file) {
        console.error("❌ [TRANSCRIPTION] No file provided");
        return res.status(400).json({ error: "Missing file" });
    }

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

    console.log("✅ [TRANSCRIPTION] Success");
    res.json({ text: data.text || "" });
  } catch (err) {
    console.error("❌ [TRANSCRIPTION] Failed:", err.message);
    res.status(500).json({ error: "Transcription failed" });
  }
});

// --- CLEAN URL HANDLER (MUST BE LAST) ---
app.get('*', (req, res, next) => {
  if (req.path.startsWith('/api')) return next();
  if (req.path.includes('.')) return next();

  if (req.path === '/') {
      return res.sendFile(path.join(__dirname, 'index.html'));
  }

  const filePath = path.join(__dirname, req.path + '.html');
  res.sendFile(filePath, (err) => {
      if (err) next(); 
  });
});

app.listen(PORT, () => {
  console.log(`🚀 [SERVER] Listening on http://localhost:${PORT}`);
});
