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

// --- 2. User Schema (Updated with Tier/Cycle in Orders) ---
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
  orders: [
    {
      orderId: String,
      amount: Number,
      date: Date,
      status: String,
      tier: String,  // Storing tier here to verify later
      cycle: String  // Storing cycle here
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
  // Keeping this simple, no strict APP_AUTH_TOKEN check right now
  if (req.method === "OPTIONS") return next();
  next();
});

const conversations = new Map();

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
          "subscription.tier": "free"
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

    if (isActive && user.subscription.validUntil && new Date() > user.subscription.validUntil) {
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
//  CASHFREE PAYMENTS (FIXED ANNUAL CALC)
// ==========================================

app.post("/api/payment/create-order", async (req, res) => {
  try {
    const { googleId, tier, cycle } = req.body; // cycle: 'monthly' or 'annual'

    const user = await User.findOne({ googleId });
    if (!user) return res.status(404).json({ error: "User not found" });

    // --- PRICE CALCULATION ---
    let amount = 1.0;

    if (tier === "pro") {
      if (cycle === "annual") amount = 3588.0; // 299 * 12
      else amount = 399.0;
    } else if (tier === "pro_plus") {
      if (cycle === "annual") amount = 7188.0; // 599 * 12
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

    // Save pending order WITH tier and cycle info
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
        // Find the specific order to get the plan details
        const order = user.orders.find((o) => o.orderId === orderId);

        user.subscription.status = "active";

        // Use the tier/cycle saved during creation
        if (order && order.tier) {
          user.subscription.tier = order.tier;

          // Calculate validity
          const days = order.cycle === "annual" ? 365 : 30;
          user.subscription.validUntil = new Date(
            Date.now() + days * 24 * 60 * 60 * 1000
          );
        } else {
          // Fallback logic if schema wasn't updated yet
          if (data.order_amount >= 5000) {
            user.subscription.tier = "pro_plus"; // Annual Pro+
            user.subscription.validUntil = new Date(
              Date.now() + 365 * 24 * 60 * 60 * 1000
            );
          } else if (data.order_amount >= 3000) {
            user.subscription.tier = "pro"; // Annual Pro
            user.subscription.validUntil = new Date(
              Date.now() + 365 * 24 * 60 * 60 * 1000
            );
          } else if (data.order_amount >= 900) {
            user.subscription.tier = "pro_plus"; // Monthly Pro+
            user.subscription.validUntil = new Date(
              Date.now() + 30 * 24 * 60 * 60 * 1000
            );
          } else {
            user.subscription.tier = "pro"; // Monthly Pro
            user.subscription.validUntil = new Date(
              Date.now() + 30 * 24 * 60 * 60 * 1000
            );
          }
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

async function callOpenAI(path, options) {
  const url = `https://api.openai.com${path}`;
  const headers = {
    Authorization: `Bearer ${OPENAI_API_KEY}`,
    ...(options.headers || {})
  };

  // Only set JSON content-type when NOT sending FormData
  if (!(options.body instanceof FormData)) {
    headers["Content-Type"] = "application/json";
  }

  const res = await fetch(url, { ...options, headers });
  const text = await res.text();
  let json;
  try {
    json = JSON.parse(text);
  } catch {
    json = text;
  }

  if (!res.ok) {
    console.error("OpenAI error:", res.status, json);
    throw new Error(
      `OpenAI error ${res.status}: ${
        typeof json === "string" ? json : JSON.stringify(json)
      }`
    );
  }
  return json;
}

// ---------- NON-STREAM CHAT (supports screenshot) ----------
app.post("/api/chat", async (req, res) => {
  const { conversationId, message } = req.body || {};
  const role = message?.role;
  const content = message?.content;
  const screenshot = message?.screenshot;

  if (!role || (!content && !screenshot)) {
    return res.status(400).json({ error: "Invalid Body" });
  }

  let convId = conversationId || `conv_${Date.now()}`;
  const history = conversations.get(convId) || [];

  // Build multimodal message if screenshot present
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

  try {
    const data = await callOpenAI("/v1/chat/completions", {
      method: "POST",
      body: JSON.stringify({
        model: "gpt-4o-mini",
        messages: history,
        temperature: 0.6
      })
    });

    const reply = data.choices?.[0]?.message?.content || "";
    history.push({ role: "assistant", content: reply });
    conversations.set(convId, history);

    res.json({ reply, conversationId: convId });
  } catch (err) {
    console.error("Chat Error:", err);
    res.status(500).json({ error: "OpenAI failed" });
  }
});

// ---------- STREAM CHAT (supports screenshot) ----------
app.post("/api/chat-stream", async (req, res) => {
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

    if (!openaiRes.ok || !openaiRes.body) {
      console.error("OpenAI stream error:", openaiRes.status);
      res.statusCode = 500;
      res.end("OpenAI Error");
      return;
    }

    for await (const chunk of openaiRes.body) {
      res.write(chunk);
    }
    res.end();
  } catch (err) {
    console.error("Stream Error:", err);
    res.statusCode = 500;
    res.end("Stream Error");
  }
});

// ---------- TRANSCRIBE ----------
app.post("/api/transcribe", upload.single("file"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: "Missing file" });

    const formData = new FormData();
    formData.append(
      "file",
      new Blob([req.file.buffer], { type: "audio/wav" }),
      "audio.wav"
    );
    formData.append("model", "whisper-1");

    const data = await callOpenAI("/v1/audio/transcriptions", {
      method: "POST",
      body: formData
    });

    res.json({ text: data.text || "" });
  } catch (err) {
    console.error("Whisper Error:", err);
    res.status(500).json({ error: "Whisper failed" });
  }
});

app.listen(PORT, () => {
  console.log(`✅ Backend listening on http://localhost:${PORT}`);
});
