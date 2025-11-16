// backend/server.js
require("dotenv").config();

const express = require("express");
const cors = require("cors");
const multer = require("multer");

const upload = multer(); // in-memory storage

const app = express();

app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 4000;
const OPENAI_API_KEY = process.env.OPENAI_API_KEY;
const APP_AUTH_TOKEN = process.env.APP_AUTH_TOKEN || "";

if (!OPENAI_API_KEY) {
  console.error("❌ OPENAI_API_KEY missing in backend/.env");
  process.exit(1);
}

// --------- Simple auth so only your app can hit the backend ---------
app.use((req, res, next) => {
  // If token not configured, auth is effectively off
  if (!APP_AUTH_TOKEN) return next();

  // Let CORS preflight pass
  if (req.method === "OPTIONS") return next();

  const token = req.header("x-whis-auth");

  if (token !== APP_AUTH_TOKEN) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  next();
});

// --------- In-memory conversation store ---------
// Map<conversationId, Array<{role, content}>>
const conversations = new Map();

/**
 * Helper to call OpenAI using Node 18+ global fetch.
 * Handles JSON OR FormData body.
 */
async function callOpenAI(path, options) {
  const url = `https://api.openai.com${path}`;

  const headers = {
    Authorization: `Bearer ${OPENAI_API_KEY}`,
    ...(options.headers || {})
  };

  // Only set JSON Content-Type if body is not FormData
  if (!(options.body instanceof FormData)) {
    headers["Content-Type"] = "application/json";
  }

  const res = await fetch(url, {
    ...options,
    headers
  });

  const text = await res.text();
  let json;
  try {
    json = JSON.parse(text);
  } catch {
    json = text;
  }

  if (!res.ok) {
    console.error("OpenAI error:", res.status, json);
    const msg = typeof json === "string" ? json : JSON.stringify(json, null, 2);
    throw new Error(`OpenAI error ${res.status}: ${msg}`);
  }

  return json;
}

/**
 * POST /api/chat
 * Body: { conversationId?: string, message: { role, content } }
 * Response: { reply: string, conversationId: string }
 */
app.post("/api/chat", async (req, res) => {
  const { conversationId, message } = req.body || {};

  if (!message || !message.role || !message.content) {
    return res
      .status(400)
      .json({ error: "Body must contain message { role, content }" });
  }

  // Resolve or create conversation ID
  let convId = conversationId;
  if (!convId) {
    convId = `conv_${Date.now()}_${Math.random()
      .toString(16)
      .slice(2)}`;
  }

  const history = conversations.get(convId) || [];

  // Append user message
  history.push({ role: message.role, content: message.content });

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

    // Append assistant reply and store back
    history.push({ role: "assistant", content: reply });
    conversations.set(convId, history);

    res.json({ reply, conversationId: convId });
  } catch (err) {
    console.error("Backend /api/chat error:", err);
    res.status(500).json({ error: "Server failed to call OpenAI chat." });
  }
});

/**
 * POST /api/chat-stream
 * Body: { conversationId?: string, message: { role, content } }
 * Response: streamed plain text (tokens concatenated)
 */
app.post("/api/chat-stream", async (req, res) => {
  const { conversationId, message } = req.body || {};

  if (!message || !message.role || !message.content) {
    return res
      .status(400)
      .json({ error: "Body must contain message { role, content }" });
  }

  let convId = conversationId;
  if (!convId) {
    convId = `conv_${Date.now()}_${Math.random()
      .toString(16)
      .slice(2)}`;
  }

  const history = conversations.get(convId) || [];
  history.push({ role: message.role, content: message.content });

  // Tell client which conversation this stream belongs to
  res.setHeader("x-conversation-id", convId);

  // Streaming headers
  res.setHeader("Content-Type", "text/plain; charset=utf-8");
  res.setHeader("Transfer-Encoding", "chunked");
  res.setHeader("Cache-Control", "no-cache");

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

    if (!openaiRes.ok || !openaiRes.body) {
      const text = await openaiRes.text();
      console.error("OpenAI stream error:", openaiRes.status, text);
      res.statusCode = 500;
      res.end("OpenAI streaming error");
      return;
    }

    const decoder = new TextDecoder("utf-8");
    let fullReply = "";

    for await (const chunk of openaiRes.body) {
      const str = decoder.decode(chunk);
      const lines = str
        .split("\n")
        .map((l) => l.trim())
        .filter((l) => l.startsWith("data: "));

      for (const line of lines) {
        const payload = line.replace(/^data:\s*/, "");
        if (payload === "[DONE]") {
          // store final reply in conversation
          conversations.set(convId, [
            ...history,
            { role: "assistant", content: fullReply }
          ]);
          res.end();
          return;
        }

        try {
          const parsed = JSON.parse(payload);
          const delta = parsed.choices?.[0]?.delta?.content || "";
          if (delta) {
            fullReply += delta;
            res.write(delta); // push to client
          }
        } catch (e) {
          console.error("Failed to parse OpenAI stream chunk:", payload);
        }
      }
    }

    // Stream ended without explicit [DONE]
    conversations.set(convId, [
      ...history,
      { role: "assistant", content: fullReply }
    ]);
    res.end();
  } catch (err) {
    console.error("/api/chat-stream error:", err);
    res.statusCode = 500;
    res.end("Server failed to call OpenAI stream.");
  }
});

/**
 * POST /api/transcribe
 * multipart/form-data with field "file"
 * Response: { text: string }
 */
app.post("/api/transcribe", upload.single("file"), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: "Missing 'file' field" });
    }

    const file = req.file;

    const formData = new FormData();
    const blob = new Blob([file.buffer], {
      type: file.mimetype || "audio/wav"
    });

    formData.append("file", blob, file.originalname || "audio.wav");
    formData.append("model", "whisper-1");
    formData.append("language", "en");
    formData.append("temperature", "0");

    const data = await callOpenAI("/v1/audio/transcriptions", {
      method: "POST",
      body: formData
    });

    res.json({ text: data.text || "" });
  } catch (err) {
    console.error("Backend /api/transcribe error:", err);
    res.status(500).json({ error: "Server failed to call OpenAI Whisper." });
  }
});

app.listen(PORT, () => {
  console.log(`✅ Backend listening on http://localhost:${PORT}`);
});
