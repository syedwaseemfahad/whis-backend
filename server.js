require("dotenv").config();

const express = require("express");
const cors = require("cors");
const multer = require("multer");
const mongoose = require("mongoose");
const Razorpay = require("razorpay");
const crypto = require("crypto");

// --- CONFIGURATION ---
const PORT = process.env.PORT || 4000;
const OPENAI_API_KEY = process.env.OPENAI_API_KEY;
const MONGODB_URI = process.env.MONGODB_URI || "mongodb://localhost:27017/whis-app";
const UI_API = process.env.UI_API || "http://localhost:5500"; 

// Razorpay Config
const RAZORPAY_KEY_ID = process.env.RAZORPAY_KEY_ID;
const RAZORPAY_KEY_SECRET = process.env.RAZORPAY_KEY_SECRET;

if (!OPENAI_API_KEY) {
  console.error("⚠️ OPENAI_API_KEY missing in backend/.env");
}
if (!RAZORPAY_KEY_ID || !RAZORPAY_KEY_SECRET) {
  console.error("⚠️ RAZORPAY_KEY_ID or RAZORPAY_KEY_SECRET missing in backend/.env");
}

const razorpay = new Razorpay({
  key_id: RAZORPAY_KEY_ID,
  key_secret: RAZORPAY_KEY_SECRET,
});

const upload = multer({ storage: multer.memoryStorage() });
const app = express();

app.use(cors());
app.use(express.json({ limit: "50mb" }));

// --- 1. MongoDB Connection ---
mongoose
  .connect(MONGODB_URI)
  .then(() => console.log("✅ Connected to MongoDB"))
  .catch((err) => console.error("❌ MongoDB connection error:", err));

// --- 2. User Schema (Expanded for detailed tracking) ---
const userSchema = new mongoose.Schema({
  googleId: { type: String, unique: true, required: true },
  email: { type: String, required: true },
  name: String,
  avatarUrl: String,
  phone: String, // Added to track user phone if provided
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
      orderId: String,          // Razorpay Order ID
      paymentId: String,        // Razorpay Payment ID
      signature: String,        // Razorpay Signature
      amount: Number,
      currency: String,
      date: Date,
      status: String,           // created, paid, failed
      tier: String, 
      cycle: String,
      method: String,           // card, upi, netbanking, etc.
      receipt: String,
      notes: Object             // Extra metadata
    }
  ],
  createdAt: { type: Date, default: Date.now },
  lastLogin: Date
});

const User = mongoose.model("User", userSchema);

// --------- Middleware ---------
app.use((req, res, next) => {
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

  // Limit: 10
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
    const { token, tokens } = req.body;
    const idToken = token || (tokens && tokens.id_token);

    if (!idToken) {
        return res.status(400).json({ error: "Missing ID Token in payload" });
    }

    const googleRes = await fetch(`https://oauth2.googleapis.com/tokeninfo?id_token=${idToken}`);
    if (!googleRes.ok) {
        return res.status(401).json({ error: "Invalid Google Token" });
    }

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
    console.error("Auth Error:", err);
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
    const isActive = user.subscription.status === "active";
    if (isActive && user.subscription.validUntil && new Date() > user.subscription.validUntil) {
      user.subscription.status = "inactive";
      user.subscription.tier = "free";
      await user.save();
    }

    // 2. Check Free Usage Daily Reset
    const today = new Date().toISOString().slice(0, 10);
    let dirty = false;
    
    if (!user.freeUsage) {
        user.freeUsage = { count: 0, lastDate: today };
        dirty = true;
    }
    
    if (user.freeUsage.lastDate !== today) {
        user.freeUsage.count = 0;
        user.freeUsage.lastDate = today;
        dirty = true;
    }

    if (dirty) await user.save();

    res.json({
      active: user.subscription.status === "active",
      tier: user.subscription.tier,
      validUntil: user.subscription.validUntil,
      freeUsage: user.freeUsage,
      orders: user.orders ? user.orders.sort((a,b) => new Date(b.date) - new Date(a.date)) : []
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to check status" });
  }
});

// 3. CREATE RAZORPAY ORDER
app.post("/api/payment/create-order", async (req, res) => {
  try {
    const { googleId, tier, cycle } = req.body; 
    const user = await User.findOne({ googleId });
    if (!user) return res.status(404).json({ error: "User not found" });

    let amount = 1.0;
    // Amounts in PAISE (Razorpay uses smallest currency unit)
    if (tier === "pro") amount = (cycle === "annual") ? 4788.0 : 799.0;
    else if (tier === "pro_plus") amount = (cycle === "annual") ? 11988.0 : 1999.0;

    const amountInPaise = Math.round(amount * 100);
    const receiptId = `rcpt_${Date.now()}_${Math.floor(Math.random() * 1000)}`;

    const options = {
      amount: amountInPaise,
      currency: "INR",
      receipt: receiptId,
      notes: {
        userId: googleId,
        tier: tier,
        cycle: cycle,
        userEmail: user.email
      }
    };

    const order = await razorpay.orders.create(options);

    if (!order) return res.status(500).json({ error: "Razorpay order creation failed" });

    // Store initial order attempt
    user.orders.push({ 
      orderId: order.id, 
      amount: amount, 
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
      key_id: RAZORPAY_KEY_ID, // Send key_id to frontend
      user_name: user.name,
      user_email: user.email,
      user_contact: user.phone || "" 
    });
  } catch (err) {
    console.error("Create Order Error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// 4. VERIFY RAZORPAY PAYMENT
app.post("/api/payment/verify", async (req, res) => {
  try {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body;

    const body = razorpay_order_id + "|" + razorpay_payment_id;
    const expectedSignature = crypto
      .createHmac("sha256", RAZORPAY_KEY_SECRET)
      .update(body.toString())
      .digest("hex");

    const isAuthentic = expectedSignature === razorpay_signature;

    if (isAuthentic) {
      const user = await User.findOne({ "orders.orderId": razorpay_order_id });
      if (!user) return res.status(404).json({ error: "Order not found attached to user" });

      const order = user.orders.find((o) => o.orderId === razorpay_order_id);
      
      // Fetch Detailed Payment Info from Razorpay to store method (UPI/Card etc)
      let paymentMethod = "unknown";
      try {
        const paymentDetails = await razorpay.payments.fetch(razorpay_payment_id);
        paymentMethod = paymentDetails.method;
        if(paymentDetails.contact && !user.phone) {
            user.phone = paymentDetails.contact; // Save phone if we didn't have it
        }
      } catch (e) {
        console.error("Could not fetch extended payment details", e);
      }

      // Update User Subscription
      user.subscription.status = "active";
      user.subscription.tier = order?.tier || "pro";
      const days = order?.cycle === "annual" ? 365 : 30;
      user.subscription.validUntil = new Date(Date.now() + days * 24 * 60 * 60 * 1000);

      // Update Order Details
      if (order) {
        order.status = "paid";
        order.paymentId = razorpay_payment_id;
        order.signature = razorpay_signature;
        order.method = paymentMethod;
      }
      
      await user.save();
      return res.json({ status: "success", success: true });
    } else {
      return res.status(400).json({ status: "failure", success: false, error: "Invalid Signature" });
    }
  } catch (err) {
    console.error("Verification Error:", err);
    res.status(500).json({ error: "Verification failed" });
  }
});

// 5. STREAM CHAT
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

  if (screenshot && !screenshot.startsWith("data:image")) {
      screenshot = `data:image/png;base64,${screenshot}`;
  }

  let convId = conversationId || `conv_${Date.now()}`;
  const history = conversations.get(convId) || [];

  let newMessage;
  if (screenshot) {
    const parts = [];
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
      res.statusCode = 500;
      res.end(`OpenAI Error: ${openaiRes.status} - ${errText}`);
      return;
    }

    for await (const chunk of openaiRes.body) {
      res.write(chunk);
    }
    res.end();
  } catch (err) {
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
    res.status(500).json({ error: "Transcription failed" });
  }
});

app.listen(PORT, () => {
  console.log(`✅ Backend listening on http://localhost:${PORT}`);
});
