require("dotenv").config();
const express = require("express");
const cors = require("cors");
const multer = require("multer");
const mongoose = require("mongoose");
// Note: If using Node.js v18+, 'fetch' is built-in. 
// If using Node <18, uncomment the line below and run: npm install node-fetch
// const fetch = require("node-fetch");

// --- CONFIGURATION ---
const PORT = process.env.PORT || 4000;
const OPENAI_API_KEY = process.env.OPENAI_API_KEY;
const MONGODB_URI = process.env.MONGODB_URI || "mongodb://localhost:27017/whis-app";

// The URL where your frontend is hosted (for payment redirects)
// In production, change this to your actual domain (e.g., https://whis.ai)
const UI_API = process.env.UI_API || "http://localhost:5500"; 

// Cashfree Payment Config
const CASHFREE_APP_ID = process.env.CASHFREE_APP_ID;
const CASHFREE_SECRET_KEY = process.env.CASHFREE_SECRET_KEY;
const CASHFREE_ENV = process.env.CASHFREE_ENV || "SANDBOX"; // 'SANDBOX' or 'PRODUCTION'
const CASHFREE_URL = CASHFREE_ENV === "PRODUCTION" 
    ? "https://api.cashfree.com/pg" 
    : "https://sandbox.cashfree.com/pg";

if (!OPENAI_API_KEY) console.warn("⚠️ OPENAI_API_KEY is missing in .env");

// Multer setup for audio uploads (stores in memory buffer)
const upload = multer({ storage: multer.memoryStorage() });

const app = express();

// Middleware
app.use(cors());
// Allow larger payloads for base64 screenshots
app.use(express.json({ limit: "10mb" }));

// --- MONGODB CONNECTION ---
mongoose.connect(MONGODB_URI)
  .then(() => console.log("✅ Connected to MongoDB"))
  .catch((err) => console.error("❌ MongoDB connection error:", err));

// --- USER SCHEMA ---
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

// --- HELPER: USAGE TRACKING ---
async function checkAndIncrementUsage(googleId) {
  const today = new Date().toISOString().slice(0, 10);
  const user = await User.findOne({ googleId });
  
  if (!user) return { allowed: false, error: "User not found" };

  // 1. Check Paid Status
  if (user.subscription.status === 'active' && ['pro', 'pro_plus'].includes(user.subscription.tier)) {
    // Check if expired
    if (user.subscription.validUntil && new Date() > user.subscription.validUntil) {
        // Expired: Downgrade logic
        user.subscription.status = 'inactive';
        user.subscription.tier = 'free';
        await user.save();
        // Continue to Free Tier check below...
    } else {
        // Active Pro/Pro+: Unlimited
        return { allowed: true, tier: user.subscription.tier };
    }
  }

  // 2. Free Tier Logic
  // Reset counter if it's a new day
  if (user.freeUsage.lastDate !== today) {
    user.freeUsage.count = 0;
    user.freeUsage.lastDate = today;
  }

  // Check Limit
  if (user.freeUsage.count >= 5) {
    return { allowed: false, error: "Daily limit reached" };
  }

  // Increment
  user.freeUsage.count += 1;
  await user.save();
  
  return { allowed: true, tier: 'free', remaining: 5 - user.freeUsage.count };
}

// ================= API ROUTES =================

// --- 1. AUTHENTICATION ---
app.post("/api/auth/google", async (req, res) => {
  try {
    const { token } = req.body;
    if (!token) return res.status(400).json({ error: "Missing token" });

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
    console.error("Auth Error:", err);
    res.status(500).json({ error: "Auth failed" });
  }
});

// --- 2. USER PROFILE & STATUS ---
app.get("/api/user/status", async (req, res) => {
  try {
    const googleId = req.headers["x-google-id"];
    if (!googleId) return res.status(401).json({ error: "Not authenticated" });

    const user = await User.findOne({ googleId });
    if (!user) return res.json({ active: false, tier: 'free' });

    // Expiry Check Logic
    const isActive = user.subscription.status === "active";
    if (isActive && user.subscription.validUntil && new Date() > user.subscription.validUntil) {
      user.subscription.status = "inactive";
      user.subscription.tier = "free";
      await user.save();
    }

    res.json({
      active: user.subscription.status === "active",
      tier: user.subscription.tier,
      validUntil: user.subscription.validUntil,
      freeUsage: user.freeUsage,
      orders: user.orders.sort((a,b) => new Date(b.date) - new Date(a.date)) // Newest orders first
    });
  } catch (err) {
    console.error("Status Error:", err);
    res.status(500).json({ error: "Status check failed" });
  }
});

// --- 3. CREATE PAYMENT ORDER (Cashfree) ---
app.post("/api/payment/create-order", async (req, res) => {
  try {
    const { googleId, tier, cycle } = req.body; 
    const user = await User.findOne({ googleId });
    if (!user) return res.status(404).json({ error: "User not found" });

    let amount = 1.0; 
    
    // Pricing Logic
    if (tier === "pro") {
        amount = (cycle === "annual") ? 4788.0 : 799.0;
    } else if (tier === "pro_plus") {
        amount = (cycle === "annual") ? 11988.0 : 1999.0;
    }

    const orderId = `order_${Date.now()}_${Math.floor(Math.random() * 1000)}`;

    // Call Cashfree API
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
        customer_details: { 
            customer_id: googleId, 
            customer_email: user.email, 
            customer_phone: "9999999999" // Required by Cashfree sandbox
        },
        order_meta: { 
            return_url: `${UI_API}/payment.html?order_id=${orderId}` 
        }
      })
    });

    const data = await response.json();
    if (!response.ok) {
        console.error("Cashfree Error:", data);
        return res.status(500).json({ error: data.message || "Payment init failed" });
    }

    // Save PENDING order to DB
    user.orders.push({ orderId, amount, date: new Date(), status: "PENDING", tier, cycle });
    await user.save();

    res.json({ payment_session_id: data.payment_session_id, order_id: orderId });
  } catch (err) {
    console.error("Payment Create Error:", err);
    res.status(500).json({ error: "Payment creation failed" });
  }
});

// --- 4. VERIFY PAYMENT ---
app.post("/api/payment/verify", async (req, res) => {
  try {
    const { orderId } = req.body;
    
    // Check status with Cashfree
    const response = await fetch(`${CASHFREE_URL}/orders/${orderId}`, {
      headers: { "x-api-version": "2023-08-01", "x-client-id": CASHFREE_APP_ID, "x-client-secret": CASHFREE_SECRET_KEY }
    });
    const data = await response.json();

    if (data.order_status === "PAID") {
      const user = await User.findOne({ "orders.orderId": orderId });
      if (user) {
        const order = user.orders.find((o) => o.orderId === orderId);
        
        // Update Subscription
        user.subscription.status = "active";
        user.subscription.tier = order?.tier || "pro";
        
        // Calculate Validity (30 days vs 365 days)
        const days = order?.cycle === "annual" ? 365 : 30;
        user.subscription.validUntil = new Date(Date.now() + days * 24 * 60 * 60 * 1000);
        
        // Update Order Status
        if (order) order.status = "PAID";
        
        await user.save();
        return res.json({ status: "PAID", success: true });
      }
    }
    res.json({ status: data.order_status, success: false });
  } catch (err) {
    console.error("Verify Error:", err);
    res.status(500).json({ error: "Verification failed" });
  }
});

// --- 5. CHAT STREAM (WITH FULL LOGIC) ---
// This handles text + images and enforces the 5-message limit for free users
app.post("/api/chat-stream", async (req, res) => {
  const googleId = req.headers["x-google-id"];
  
  // A. Check Usage Limit
  if (googleId) {
    const check = await checkAndIncrementUsage(googleId);
    if (!check.allowed) {
        return res.status(403).json({ error: "Daily limit reached. Please upgrade to Pro." });
    }
  }

  // B. Parse Request
  const { conversationId, message } = req.body || {};
  const role = message?.role || "user";
  const content = message?.content;
  const screenshot = message?.screenshot; // Base64 image string

  if (!content && !screenshot) {
    return res.status(400).json({ error: "No content provided" });
  }

  // C. Construct OpenAI Messages Array
  // (In a real app, you might fetch previous history from DB here using conversationId)
  const messages = [
      { role: "system", content: "You are Whis, an expert interview assistant. Be concise. Provide specific, high-level answers. Do not be verbose." }
  ];

  let userMessageContent;
  
  // Handle Vision (Image)
  if (screenshot) {
    userMessageContent = [
      { type: "text", text: content || "What is happening on this screen? Answer the question if visible." },
      { type: "image_url", image_url: { url: screenshot } } 
    ];
  } else {
    userMessageContent = content;
  }

  messages.push({ role: "user", content: userMessageContent });

  // D. Setup Headers for Streaming
  res.setHeader("Content-Type", "text/plain; charset=utf-8");
  res.setHeader("Transfer-Encoding", "chunked");

  try {
    // E. Call OpenAI API
    const openaiRes = await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${OPENAI_API_KEY}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        model: "gpt-4o-mini", // Efficient model for speed
        messages: messages,
        temperature: 0.6,
        stream: true
      })
    });

    if (!openaiRes.ok) {
      const errText = await openaiRes.text();
      console.error("OpenAI Error:", openaiRes.status, errText);
      res.write(`Error: ${errText}`);
      return res.end();
    }

    // F. Stream the response back to the client
    // Note: Node-fetch body is an async iterator
    for await (const chunk of openaiRes.body) {
      res.write(chunk);
    }
    res.end();

  } catch (err) {
    console.error("Stream Catch Error:", err);
    res.write("Internal Server Error during stream");
    res.end();
  }
});

// --- 6. AUDIO TRANSCRIPTION ---
app.post("/api/transcribe", upload.single("file"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: "Missing file" });

    // Create FormData for OpenAI
    // We need to import 'form-data' package if using Node <18, 
    // but assuming modern Node environment or native FormData (Node 18+)
    const formData = new FormData();
    
    // Create a Blob from the buffer (Node 18+)
    const audioBlob = new Blob([req.file.buffer], { type: req.file.mimetype });
    formData.append("file", audioBlob, req.file.originalname || "audio.webm");
    formData.append("model", "whisper-1");
    formData.append("language", "en");

    const openaiRes = await fetch("https://api.openai.com/v1/audio/transcriptions", {
        method: "POST",
        headers: {
            Authorization: `Bearer ${OPENAI_API_KEY}`
            // Do NOT set Content-Type here; fetch/FormData sets the boundary automatically
        },
        body: formData
    });
    
    const data = await openaiRes.json();
    if (!openaiRes.ok) {
        console.error("Transcription API Error:", data);
        throw new Error(data.error?.message || "OpenAI Error");
    }

    res.json({ text: data.text || "" });
  } catch (err) {
    console.error("Transcribe Error:", err);
    res.status(500).json({ error: "Transcription failed" });
  }
});

app.listen(PORT, () => console.log(`✅ Backend listening on http://localhost:${PORT}`));
