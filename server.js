// backend/server.js
require("dotenv").config();

const express = require("express");
const cors = require("cors");
const multer = require("multer");
const mongoose = require("mongoose");

// --- CONFIGURATION ---
const PORT = process.env.PORT || 4000;
const OPENAI_API_KEY = process.env.OPENAI_API_KEY;
const APP_AUTH_TOKEN = process.env.APP_AUTH_TOKEN || "";
const MONGODB_URI =
  process.env.MONGODB_URI || "mongodb://localhost:27017/whis-app";
const UI_API =
  process.env.UI_API || "https://syedwaseemfahad.github.io/whis-ai-site";

// Cashfree Config
const CASHFREE_APP_ID = process.env.CASHFREE_APP_ID;
const CASHFREE_SECRET_KEY = process.env.CASHFREE_SECRET_KEY;
const CASHFREE_ENV = process.env.CASHFREE_ENV || "SANDBOX";
const CASHFREE_URL =
  CASHFREE_ENV === "PRODUCTION"
    ? "https://api.cashfree.com/pg"
    : "https://sandbox.cashfree.com/pg";

if (!OPENAI_API_KEY) {
  console.error("⚠️ OPENAI_API_KEY missing in backend/.env");
}

const upload = multer();
const app = express();

app.use(cors());
// Allow larger JSON payloads (for screenshots as base64 URLs)
app.use(express.json({ limit: "5mb" }));

// --- 1. MongoDB Connection ---
mongoose
  .connect(MONGODB_URI)
  .then(() => console.log("✅ Connected to MongoDB"))
  .catch((err) => console.error("❌ MongoDB connection error:", err));

// --- 2. User Schema (Updated with Free Usage Tracking) ---
const userSchema = new mongoose.Schema({
  googleId: { type: String, unique: true, required: true },
  email: { type: String, required: true },
  name: String,
  avatarUrl: String,
  subscription: {
    status: {
      type: String,
      enum: ["active", "inactive", "past_due"],
      default: "inactive"
    },
    tier: {
      type: String,
      enum: ["free", "pro", "pro_plus"],
      default: "free"
    },
    cycle: {
      type: String,
      enum: ["monthly", "annual"],
      default: "monthly"
    },
    validUntil: Date
  },
  // NEW: Track free usage server-side
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

// --------- Middleware ---------
app.use((req, res, next) => {
  // Auth-free routes
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

// --- Helper: Check & Increment Free Usage ---
async function checkAndIncrementUsage(googleId) {
  const today = new Date().toISOString().slice(0, 10); // YYYY-MM-DD
  const user = await User.findOne({ googleId });
  
  if (!user) return { allowed: false, error: "User not found" };

  // 1. If paid and active, allow unlimited
  if (user.subscription.status === 'active' && ['pro', 'pro_plus'].includes(user.subscription.tier)) {
    return { allowed: true, tier: user.subscription.tier };
  }

  // 2. Free tier logic
  // Reset if new day
  if (user.freeUsage.lastDate !== today) {
    user.freeUsage.count = 0;
    user.freeUsage.lastDate = today;
  }

  // Check limit (5 per day)
  if (user.freeUsage.count >= 5) {
    return { allowed: false, error: "Daily limit reached" };
  }

  // Increment
  user.freeUsage.count += 1;
  await user.save();
  
  return { allowed: true, tier: 'free', remaining: 5 - user.freeUsage.count };
}

// ==========================================
//  AUTH & USER APIs
// ==========================================

app.post("/api/auth/google", async (req, res) => {
  try {
    const { token } = req.body;
    if (!token) return res.status(400).json({ error: "Missing google token" });

    const googleRes = await fetch(
      `https://oauth2.googleapis.com/tokeninfo?id_token=${token}`
    );
    if (!googleRes.ok)
      return res.status(401).json({ error: "Invalid Google Token" });

    const payload = await googleRes.json();
    const { sub: googleId, email, name, picture: avatarUrl } = payload;

    const user = await User.findOneAndUpdate(
      { googleId },
      {
        email,
        name,
        avatarUrl,
        lastLogin: new Date(),
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

app.get("/api/user/status", async (req, res) => {
  try {
    const googleId = req.headers["x-google-id"];
    if (!googleId) return res.status(401).json({ error: "Not authenticated" });

    const user = await User.findOne({ googleId });
    if (!user) return res.json({ active: false, tier: null });

    const isActive = user.subscription.status === "active";

    if (
      isActive &&
      user.subscription.validUntil &&
      new Date() > user.subscription.validUntil
    ) {
      user.subscription.status = "inactive";
      await user.save();
      return res.json({
        active: false,
        tier: user.subscription.tier,
        expired: true
      });
    }

    res.json({
      active: isActive,
      tier: user.subscription.tier,
      details: user.subscription
    });
  } catch (err) {
    console.error("Status Check Error:", err);
    res.status(500).json({ error: "Failed to check status" });
  }
});

// ==========================================
//  CASHFREE PAYMENTS
// ==========================================

app.post("/api/payment/create-order", async (req, res) => {
  try {
    const { googleId, tier, cycle } = req.body; 

    const user = await User.findOne({ googleId });
    if (!user) return res.status(404).json({ error: "User not found" });

    // --- PRICE CALCULATION ---
    let amount = 1.0;

    if (tier === "pro") {
      if (cycle === "annual") amount = 3588.0; 
      else amount = 399.0;
    } else if (tier === "pro_plus") {
      if (cycle === "annual") amount = 7188.0; 
      else amount = 999.0;
    }

    const orderId = `order_${Date.now()}_${Math.floor(Math.random() * 1000)}`;

    const payload = {
      order_id: orderId,
      order_amount: amount,
      order_currency: "INR",
      customer_details: {
        customer_id: googleId,
        customer_email: user.email,
        customer_phone: "9999999999"
      },
      order_meta: {
        return_url: `${UI_API}/payment.html?order_id=${orderId}`
      }
    };

    const response = await fetch(`${CASHFREE_URL}/orders`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-version": "2023-08-01",
        "x-client-id": CASHFREE_APP_ID,
        "x-client-secret": CASHFREE_SECRET_KEY
      },
      body: JSON.stringify(payload)
    });

    const data = await response.json();

    if (!response.ok) {
      console.error("Cashfree Failed:", data);
      return res
        .status(500)
        .json({ error: data.message || "Payment creation failed" });
    }

    // Save pending order
    user.orders.push({
      orderId,
      amount,
      date: new Date(),
      status: "PENDING",
      tier: tier,
      cycle: cycle
    });
    await user.save();

    res.json({
      payment_session_id: data.payment_session_id,
      order_id: orderId
    });
  } catch (err) {
    console.error("Create Order Error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.post("/api/payment/verify", async (req, res) => {
  try {
    const { orderId } = req.body;

    const response = await fetch(`${CASHFREE_URL}/orders/${orderId}`, {
      headers: {
        "x-api-version": "2023-08-01",
        "x-client-id": CASHFREE_APP_ID,
        "x-client-secret": CASHFREE_SECRET_KEY
      }
    });

    const data = await response.json();

    if (data.order_status === "PAID") {
      const user = await User.findOne({ "orders.orderId": orderId });

      if (user) {
        const order = user.orders.find((o) => o.orderId === orderId);

        user.subscription.status = "active";

        if (order && order.tier) {
          user.subscription.tier = order.tier;
          const days = order.cycle === "annual" ? 365 : 30;
          user.subscription.validUntil = new Date(
            Date.now() + days * 24 * 60 * 60 * 1000
          );
        } else {
          // Fallback if tier/cycle not saved
          user.subscription.tier = "pro";
          user.subscription.validUntil = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
        }

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

// ==========================================
//  AI & TRANSCRIPTION APIs
// ==========================================

// ---------- STREAM CHAT (Enforces Limit) ----------
app.post("/api/chat-stream", async (req, res) => {
  const googleId = req.headers["x-google-id"];
  
  // 1. Check Usage Limit
  if (googleId) {
    const check = await checkAndIncrementUsage(googleId);
    if (!check.allowed) {
      return res.status(403).json({ error: "Daily limit reached. Please upgrade to Pro." });
    }
  }

  const { conversationId, message } = req.body || {};
  const role = message?.role;
  const content = message?.content;
  const screenshot = message?.screenshot;

  if (!role || (!content && !screenshot)) {
    return res.status(400).json({ error: "Invalid Body" });
  }

  let convId = conversationId || `conv_${Date.now()}`;
  const history = conversations.get(convId) || [];

  let newMessage;
  if (screenshot) {
    const parts = [];
    if (content) {
      parts.push({ type: "text", text: content });
    }
    parts.push({
      type: "image_url",
      image_url: { url: screenshot }
    });
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
    const openaiRes = await fetch(
      "https://api.openai.com/v1/chat/completions",
      {
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
      }
    );

    if (!openaiRes.ok) {
      const errText = await openaiRes.text();
      console.error("OpenAI stream error:", openaiRes.status, errText);
      res.statusCode = 500;
      res.end(`OpenAI Error: ${openaiRes.status}`);
      return;
    }

    if (!openaiRes.body) {
      res.statusCode = 500;
      res.end("No body from OpenAI");
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

// ---------- TRANSCRIBE ----------
app.post("/api/transcribe", upload.single("file"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: "Missing file" });

    const mime = req.file.mimetype || "audio/webm";
    const filename = req.file.originalname || "audio.webm";

    const formData = new FormData();
    formData.append(
      "file",
      new Blob([req.file.buffer], { type: mime }),
      filename
    );

    // Use gpt-4o-transcribe or whisper-1
    formData.append("model", "gpt-4o-transcribe"); 
    formData.append("language", "en");

    // Note: Using fetch to OpenAI here
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
