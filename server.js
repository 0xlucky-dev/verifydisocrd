require("dotenv").config();
const express = require("express");
const cookieParser = require("cookie-parser");
const path = require("path");
const db = require("./database");

const app = express();
const PORT = process.env.PORT || 3000;
const API_KEY = process.env.API_KEY || "changeme";

const {
  DISCORD_CLIENT_ID,
  DISCORD_CLIENT_SECRET,
  REDIRECT_URI,
  BOT_TOKEN,
  GUILD_ID,
  VERIFIED_ROLE_ID,
  REDIRECT_AFTER_VERIFY,
} = process.env;

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(express.static(path.join(__dirname, "public")));
app.use(cookieParser());
app.set("trust proxy", true);

// ============================================================
// Rate Limiting
// ============================================================
const rateLimits = {};  // { "ip_subnet": { count, lastReset, blocked_until } }
const apiRateLimits = {}; // { "ip_subnet": { last_call, blocked_until } }

function getSubnet(ip) {
  // Get /24 subnet (first 3 octets) — e.g. "192.168.1" from "192.168.1.55"
  const parts = ip.split(".");
  if (parts.length === 4) return parts.slice(0, 3).join(".");
  return ip; // IPv6 or unknown — use full
}

function getClientIp(req) {
  return (req.headers["x-forwarded-for"] || req.ip || "unknown").split(",")[0].trim();
}

// Web rate limit: 15 requests / 60s per /24 subnet (legit user uses ~3-5)
function webRateLimit(req, res, next) {
  const ip = getClientIp(req);
  const subnet = getSubnet(ip);
  const now = Date.now();

  // Check global block first (from catch-all or API abuse)
  if (apiRateLimits[subnet] && apiRateLimits[subnet].blocked_until > now) {
    return res.status(429).send("");
  }

  if (!rateLimits[subnet]) rateLimits[subnet] = { count: 0, lastReset: now, blocked_until: 0 };
  const entry = rateLimits[subnet];

  if (entry.blocked_until > now) {
    return res.status(429).render("error", { message: "ถูกบล็อคชั่วคราว กรุณารอสักครู่" });
  }

  if (now - entry.lastReset > 60000) {
    entry.count = 0;
    entry.lastReset = now;
  }

  entry.count++;
  if (entry.count > 15) {
    entry.blocked_until = now + 600000; // block 10 min
    return res.status(429).render("error", { message: "คำขอมากเกินไป กรุณารอ 10 นาที" });
  }

  next();
}

// API rate limit: valid API key = no block. Invalid/missing key = block 6h.
function apiRateLimit(req, res, next) {
  const key = req.headers["x-api-key"] || req.query.key;
  if (key === API_KEY) {
    return next(); // valid key — no rate limit
  }

  // Invalid or missing key — block subnet 6h
  const ip = getClientIp(req);
  const subnet = getSubnet(ip);
  const now = Date.now();
  if (!apiRateLimits[subnet]) apiRateLimits[subnet] = { blocked_until: 0 };
  apiRateLimits[subnet].blocked_until = now + 6 * 3600 * 1000;
  return res.status(403).json({ error: "forbidden_blocked_6h" });
} // nginx X-Forwarded-For

// ============================================================
// Routes
// ============================================================

// Root — redirect or show info
app.get("/", webRateLimit, (req, res) => {
  res.render("verify", { oauthUrl: "#" });
});

// Landing page — fingerprint + redirect to Discord OAuth
app.get("/verify", webRateLimit, (req, res) => {
  const discordId = req.query.discord_id || "";
  const oauthUrl =
    `https://discord.com/api/oauth2/authorize` +
    `?client_id=${DISCORD_CLIENT_ID}` +
    `&redirect_uri=${encodeURIComponent(REDIRECT_URI)}` +
    `&response_type=code` +
    `&scope=identify` +
    `&state=${discordId}`;
  res.render("verify", { oauthUrl });
});

// OAuth2 callback
app.get("/callback", webRateLimit, async (req, res) => {
  const { code, state } = req.query;
  const fpHash = req.cookies?.fp_hash || req.query.fp || "no-fp";

  if (!code) return res.status(400).render("error", { message: "Missing code" });

  try {
    // Exchange code for token
    const tokenResp = await fetch("https://discord.com/api/v10/oauth2/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: DISCORD_CLIENT_ID,
        client_secret: DISCORD_CLIENT_SECRET,
        grant_type: "authorization_code",
        code,
        redirect_uri: REDIRECT_URI,
      }),
    });
    if (!tokenResp.ok) throw new Error(`Token exchange failed: ${tokenResp.status}`);
    const tokenData = await tokenResp.json();

    // Get user info
    const userResp = await fetch("https://discord.com/api/v10/users/@me", {
      headers: { Authorization: `Bearer ${tokenData.access_token}` },
    });
    if (!userResp.ok) throw new Error("Failed to get user info");
    const user = await userResp.json();

    // Capture data
    const ip = (req.headers["x-forwarded-for"] || req.ip || "unknown").split(",")[0].trim();
    const discordId = user.id;
    const username = user.username;
    const accountCreatedAt = Math.floor((Number(BigInt(discordId) >> 22n) + 1420070400000) / 1000);

    // Save to DB
    const clusterId = db.saveVerification(discordId, username, ip, fpHash, Number(accountCreatedAt));

    // Assign role
    let roleOk = false;
    if (BOT_TOKEN && GUILD_ID && VERIFIED_ROLE_ID) {
      const roleResp = await fetch(
        `https://discord.com/api/v10/guilds/${GUILD_ID}/members/${discordId}/roles/${VERIFIED_ROLE_ID}`,
        { method: "PUT", headers: { Authorization: `Bot ${BOT_TOKEN}` } }
      );
      roleOk = roleResp.status === 204 || roleResp.status === 200;
    }

    res.render("done", { username, roleOk, redirectUrl: REDIRECT_AFTER_VERIFY || "" });
  } catch (err) {
    console.error("Callback error:", err);
    res.status(500).render("error", { message: err.message });
  }
});

// API — for service-bot $daily to check cluster (anti-alt only, no log)
app.get("/api/cluster-check/:discordId", apiRateLimit, (req, res) => {
  const { discordId } = req.params;
  const result = db.clusterCheck(discordId);
  res.json(result);
});

// API — record that a user claimed $daily (so cluster check knows)
app.post("/api/claim/:discordId", apiRateLimit, (req, res) => {
  const { discordId } = req.params;
  db.recordClaim(discordId);
  res.json({ ok: true });
});

// API — admin: reset cluster record for a user (requires API key)
app.delete("/api/cluster/:discordId", apiRateLimit, (req, res) => {
  const { discordId } = req.params;
  const result = db.resetCluster(discordId);
  res.json(result);
});

// API — admin: whitelist user (exempt from cluster check)
app.post("/api/whitelist/:discordId", apiRateLimit, (req, res) => {
  const { discordId } = req.params;
  const result = db.whitelistUser(discordId);
  res.json(result);
});

// API — admin: remove whitelist
app.delete("/api/whitelist/:discordId", apiRateLimit, (req, res) => {
  const { discordId } = req.params;
  const result = db.unwhitelistUser(discordId);
  res.json(result);
});

// API — admin: get cluster info for a user (requires API key)
app.get("/api/cluster/:discordId", apiRateLimit, (req, res) => {
  const { discordId } = req.params;
  const result = db.getClusterInfo(discordId);
  res.json(result);
});

// API — legacy checkin (kept for compatibility)
app.get("/api/checkin/:discordId", apiRateLimit, (req, res) => {
  const { discordId } = req.params;
  const credits = parseInt(req.query.credits || "15");
  const cooldown = parseInt(req.query.cooldown || "24");
  const result = db.checkAndClaimCheckin(discordId, credits, cooldown);
  res.json(result);
});

// Catch-all: ANY unknown endpoint = block /24 subnet 6h
// Also check blocked subnets on all requests (except static served by express.static above)
app.use((req, res) => {
  const ip = getClientIp(req);
  const subnet = getSubnet(ip);
  const now = Date.now();
  if (!apiRateLimits[subnet]) apiRateLimits[subnet] = { blocked_until: 0 };

  // Already blocked — silent drop
  if (apiRateLimits[subnet].blocked_until > now) {
    return res.status(429).send("");
  }

  // New unknown path probe — block 6h
  apiRateLimits[subnet].blocked_until = now + 6 * 3600 * 1000;
  console.log(`[BLOCK] subnet ${subnet} probed unknown: ${req.method} ${req.path}`);
  res.status(404).send("");
});

app.listen(PORT, () => {
  console.log(`Verify-web running on http://localhost:${PORT}`);
});
