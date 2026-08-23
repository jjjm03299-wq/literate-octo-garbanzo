const express = require("express");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 5900;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const DATA_DIR = path.join(__dirname, "data");
const USERS_FILE = path.join(DATA_DIR, "users.json");
const APPS_FILE = path.join(DATA_DIR, "oauth-apps.json");
const SECRET_FILE = path.join(DATA_DIR, "oauth-secret.key");
const REVOKED_TOKENS_FILE = path.join(DATA_DIR, "revoked-tokens.json");

fs.mkdirSync(DATA_DIR, { recursive: true });

if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, "[]");
if (!fs.existsSync(APPS_FILE)) fs.writeFileSync(APPS_FILE, "[]");
if (!fs.existsSync(REVOKED_TOKENS_FILE)) fs.writeFileSync(REVOKED_TOKENS_FILE, "[]");

let OAUTH_SECRET;
if (fs.existsSync(SECRET_FILE)) {
  OAUTH_SECRET = fs.readFileSync(SECRET_FILE, "utf8").trim();
} else {
  OAUTH_SECRET = crypto.randomBytes(64).toString("hex");
  fs.writeFileSync(SECRET_FILE, OAUTH_SECRET, { mode: 0o600 });
}

console.log("OAuth secret key loaded/generated.");

const deviceCodes = new Map();

// VPN State & Data Store
let vpnConnectionState = {
  status: "disconnected",
  currentServer: null,
  assignedIp: null,
  connectedAt: null
};

let vpnHistory = [];

const vpnServers = [
  { id: "us-01", country: "United States", flag: "🇺🇸", load: "45%" },
  { id: "uk-01", country: "United Kingdom", flag: "🇬🇧", load: "30%" },
  { id: "ca-01", country: "Canada", flag: "🇨🇦", load: "20%" },
  { id: "de-01", country: "Germany", flag: "🇩🇪", load: "65%" },
  { id: "jp-01", country: "Japan", flag: "🇯🇵", load: "50%" },
  { id: "au-01", country: "Australia", flag: "🇦🇺", load: "15%" },
  { id: "fr-01", country: "France", flag: "🇫🇷", load: "40%" },
  { id: "sg-01", country: "Singapore", flag: "🇸🇬", load: "55%" },
  { id: "br-01", country: "Brazil", flag: "🇧🇷", load: "25%" },
  { id: "in-01", country: "India", flag: "🇮🇳", load: "70%" }
];

/* --------------------------------------------------
   Helpers
-------------------------------------------------- */

function readJson(file) {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    return [];
  }
}

function writeJson(file, value) {
  fs.writeFileSync(file, JSON.stringify(value, null, 2));
}

function randomHex(bytes) {
  return crypto.randomBytes(bytes).toString("hex");
}

function generateClientId() {
  return "client_" + randomHex(16);
}

function generateClientSecret() {
  return "secret_" + randomHex(32);
}

function generateDeviceCode() {
  return crypto.randomBytes(4).toString("hex").toUpperCase();
}

function hashPassword(password) {
  return crypto.createHash("sha256").update(password).digest("hex");
}

function baseUrl(req) {
  const protocol = req.headers["x-forwarded-proto"] || req.protocol;
  return `${protocol}://${req.get("host")}`;
}

function generateVpnIp() {
  const octet2 = Math.floor(Math.random() * 255);
  const octet3 = Math.floor(Math.random() * 255);
  const octet4 = Math.floor(Math.random() * 254) + 1;
  return `10.${octet2}.${octet3}.${octet4}`;
}

function isTokenRevoked(jti) {
  if (!jti) return false;
  const revoked = readJson(REVOKED_TOKENS_FILE);
  return revoked.some(item => item.jti === jti);
}

function revokeToken(jti, exp) {
  const revoked = readJson(REVOKED_TOKENS_FILE);
  if (revoked.some(item => item.jti === jti)) return;
  revoked.push({ jti, exp: exp || null, revokedAt: new Date().toISOString() });
  writeJson(REVOKED_TOKENS_FILE, revoked);
}

/* --------------------------------------------------
   Device Login HTML
-------------------------------------------------- */

const htmlContent = `
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Connect Account</title>
<style>
body { background: #111; color: #00ff66; font-family: monospace; padding: 25px; }
.container { max-width: 520px; margin: auto; background: #1b1b1b; padding: 25px; border-radius: 8px; }
h1, h2 { border-bottom: 1px solid #333; padding-bottom: 8px; }
input, button { width: 100%; box-sizing: border-box; padding: 12px; margin: 6px 0; background: #222; color: white; border: 1px solid #444; font-family: monospace; }
button { background: #0088cc; cursor: pointer; font-weight: bold; }
button:hover { background: #00aaff; }
hr { border: 0; border-top: 1px solid #333; margin: 25px 0; }
</style>
</head>
<body>
<div class="container">
<h1>Connect Account</h1>
<p>Enter your device code to connect your account.</p>
<form method="POST" action="/login/device">
<input name="device_code" placeholder="Enter your device code" required>
<h2>Login</h2>
<input name="username" placeholder="Enter username" required>
<input type="password" name="password" placeholder="Enter password" required>
<button type="submit">Connect Account</button>
</form>
<hr>
<h2>Register Account</h2>
<form method="POST" action="/api/auth/register">
<input name="username" placeholder="Enter username" required>
<input type="password" name="password" placeholder="Enter password" required>
<button type="submit">Create Account</button>
</form>
</div>
</body>
</html>
`;

/* --------------------------------------------------
   OAuth & Auth Routes
-------------------------------------------------- */

app.get("/oauth/device", (req, res) => res.send(htmlContent));
app.get("/login/device", (req, res) => res.send(htmlContent));

app.post("/oauth/device/code", (req, res) => {
  const deviceCode = randomHex(32);
  const userCode = generateDeviceCode();
  const expiresIn = 600;

  const entry = {
    deviceCode,
    userCode,
    clientId: req.body.client_id || null,
    username: null,
    status: "pending",
    createdAt: Date.now(),
    expiresAt: Date.now() + expiresIn * 1000
  };

  deviceCodes.set(deviceCode, entry);

  res.json({
    device_code: deviceCode,
    user_code: userCode,
    verification_uri: `${baseUrl(req)}/oauth/device`,
    verification_uri_complete: `${baseUrl(req)}/oauth/device?code=${userCode}`,
    expires_in: expiresIn,
    interval: 5
  });
});

app.post("/api/auth/register", (req, res) => {
  const { username, password } = req.body;
  if (typeof username !== "string" || typeof password !== "string") {
    return res.status(400).json({ error: "username_and_password_required" });
  }
  if (username.length < 3 || password.length < 8) {
    return res.status(400).json({ error: "invalid_registration", message: "Min length: username 3, password 8." });
  }

  const users = readJson(USERS_FILE);
  if (users.some(u => u.username === username)) {
    return res.status(409).json({ error: "username_already_exists" });
  }

  users.push({ id: randomHex(16), username, passwordHash: hashPassword(password), createdAt: new Date().toISOString() });
  writeJson(USERS_FILE, users);
  res.status(201).json({ status: "success", message: "Account created", username });
});

app.post("/api/auth/login", (req, res) => {
  const { username, password } = req.body;
  const users = readJson(USERS_FILE);
  const user = users.find(u => u.username === username);

  if (!user || user.passwordHash !== hashPassword(password || "")) {
    return res.status(401).json({ error: "invalid_credentials" });
  }

  const accessToken = jwt.sign({ sub: user.id, username: user.username, jti: randomHex(32) }, OAUTH_SECRET, { expiresIn: "1h" });
  res.json({ access_token: accessToken, token_type: "Bearer", expires_in: 3600 });
});

app.post("/login/device", (req, res) => {
  const { device_code, username, password } = req.body;
  if (!device_code || !username || !password) {
    return res.status(400).send("Device code, username and password are required.");
  }

  let device = null;
  for (const item of deviceCodes.values()) {
    if (item.deviceCode === device_code || item.userCode === device_code.toUpperCase()) {
      device = item;
      break;
    }
  }

  if (!device || Date.now() > device.expiresAt) {
    return res.status(400).send("Invalid or expired device code.");
  }

  const users = readJson(USERS_FILE);
  const user = users.find(u => u.username === username);
  if (!user || user.passwordHash !== hashPassword(password)) {
    return res.status(401).send("Invalid username or password.");
  }

  device.status = "approved";
  device.username = username;
  res.redirect(`/login/device/success?device_code=${encodeURIComponent(device.deviceCode)}`);
});

app.get("/login/device/success", (req, res) => {
  const { device_code } = req.query;
  const device = deviceCodes.get(device_code);
  if (!device) return res.status(404).send("Device code not found.");
  res.send(`<!DOCTYPE html><html><head><title>Device Connected</title></head><body style="background:#111;color:#00ff66;font-family:monospace;padding:30px;"><div style="max-width:600px;margin:auto;background:#1b1b1b;padding:25px;"><h1>Device Connected</h1><p>Account successfully connected: <strong>${device.username}</strong></p></div></body></html>`);
});

app.post("/oauth/apps", (req, res) => {
  const { name, redirect_uri } = req.body;
  if (!name) return res.status(400).json({ error: "application_name_required" });

  const clientId = generateClientId();
  const clientSecret = generateClientSecret();
  const apps = readJson(APPS_FILE);

  apps.push({ id: randomHex(16), name, client_id: clientId, client_secret: clientSecret, redirect_uri: redirect_uri || null, createdAt: new Date().toISOString() });
  writeJson(APPS_FILE, apps);

  res.status(201).json({ status: "success", name, client_id: clientId, client_secret: clientSecret, redirect_uri: redirect_uri || null });
});

app.post("/oauth2/token", (req, res) => {
  const { device_code, client_id, client_secret } = req.body;
  if (!device_code) return res.status(400).json({ error: "device_code_required" });

  if (client_id) {
    const apps = readJson(APPS_FILE);
    const oauthApp = apps.find(app => app.client_id === client_id && app.client_secret === client_secret);
    if (!oauthApp) return res.status(401).json({ error: "invalid_client" });
  }

  const device = deviceCodes.get(device_code);
  if (!device) return res.status(400).json({ error: "invalid_device_code" });
  if (Date.now() > device.expiresAt) {
    deviceCodes.delete(device_code);
    return res.status(400).json({ error: "expired_device_code" });
  }
  if (device.status === "pending") return res.status(428).json({ error: "authorization_pending" });
  if (device.status !== "approved") return res.status(400).json({ error: "invalid_device_state" });

  const accessToken = jwt.sign({ sub: device.username, username: device.username, device_code: device.deviceCode, jti: randomHex(32) }, OAUTH_SECRET, { expiresIn: "1h" });
  deviceCodes.delete(device_code);

  res.json({ access_token: accessToken, token_type: "Bearer", expires_in: 3600 });
});

/* --------------------------------------------------
   JWT Middleware
-------------------------------------------------- */

function authenticateJWT(req, res, next) {
  const authorization = req.headers.authorization || "";
  if (!authorization.startsWith("Bearer ")) {
    return res.status(401).json({ error: "unauthorized", message: "Bearer access token required" });
  }

  const token = authorization.substring(7);
  try {
    const decoded = jwt.verify(token, OAUTH_SECRET);
    if (decoded.jti && isTokenRevoked(decoded.jti)) {
      return res.status(401).json({ error: "invalid_token", message: "Token has been revoked" });
    }
    req.user = decoded;
    req.accessToken = token;
    next();
  } catch {
    return res.status(401).json({ error: "invalid_token", message: "Invalid or expired access token" });
  }
}

/* --------------------------------------------------
   Additional Custom Endpoints Requested
-------------------------------------------------- */

app.get("/oauth/userinfo", authenticateJWT, (req, res) => {
  res.json({ sub: req.user.username, username: req.user.username, active: true });
});

app.get("/api/whoami", authenticateJWT, (req, res) => {
  res.json({ username: req.user.username, authenticated: true });
});

app.get("/oauth/device/verify", (req, res) => {
  const { code } = req.query;
  res.json({ valid: true, user_code: code || null });
});

app.post("/activate", authenticateJWT, (req, res) => {
  res.json({ status: "activated", username: req.user.username, timestamp: new Date().toISOString() });
});

/* --------------------------------------------------
   OAuth Status Endpoint (Added)
-------------------------------------------------- */

app.get("/api/oauth/status", authenticateJWT, (req, res) => {
  res.json({
    authenticated: true,
    username: req.user.username,
    token_type: "Bearer",
    vpn_status: vpnConnectionState.status
  });
});

/* --------------------------------------------------
   VPN API Endpoints
-------------------------------------------------- */

// 1. List Servers
app.get("/api/vpn/servers", authenticateJWT, (req, res) => {
  res.json({ success: true, count: vpnServers.length, servers: vpnServers });
});

// 2. VPN Country List with Flags
app.get("/api/vpn/countries", authenticateJWT, (req, res) => {
  const countries = vpnServers.map(s => ({ country: s.country, flag: s.flag, serverId: s.id }));
  res.json({ success: true, countries });
});

// 3. Connect VPN
app.post("/api/vpn/connect", authenticateJWT, (req, res) => {
  const { serverId } = req.body;
  const targetServer = vpnServers.find(s => s.id === serverId);

  if (!targetServer) {
    return res.status(404).json({ success: false, message: "VPN Server not found" });
  }

  const assignedIp = generateVpnIp();
  vpnConnectionState = {
    status: "connected",
    currentServer: targetServer,
    assignedIp,
    connectedAt: new Date().toISOString()
  };

  vpnHistory.unshift({
    action: "CONNECTED",
    user: req.user.username,
    server: targetServer.id,
    country: targetServer.country,
    ip: assignedIp,
    timestamp: vpnConnectionState.connectedAt
  });

  res.json({
    success: true,
    message: `Connected to ${targetServer.country} ${targetServer.flag}`,
    connection: vpnConnectionState
  });
});

// 4. Disconnect VPN
app.post("/api/vpn/disconnect", authenticateJWT, (req, res) => {
  if (vpnConnectionState.status === "disconnected") {
    return res.json({ success: true, message: "VPN is already disconnected" });
  }

  const prevServer = vpnConnectionState.currentServer;
  vpnHistory.unshift({
    action: "DISCONNECTED",
    user: req.user.username,
    server: prevServer ? prevServer.id : null,
    timestamp: new Date().toISOString()
  });

  vpnConnectionState = {
    status: "disconnected",
    currentServer: null,
    assignedIp: null,
    connectedAt: null
  };

  res.json({ success: true, message: "VPN disconnected successfully", connection: vpnConnectionState });
});

// 5. VPN Status
app.get("/api/vpn/status", authenticateJWT, (req, res) => {
  res.json({ success: true, connection: vpnConnectionState });
});

// 6. VPN History
app.get("/api/vpn/history", authenticateJWT, (req, res) => {
  res.json({ success: true, history: vpnHistory });
});

/* --------------------------------------------------
   Standard Auth Management Endpoints
-------------------------------------------------- */

app.post("/api/auth/logout", authenticateJWT, (req, res) => {
  if (!req.user.jti) return res.status(400).json({ error: "token_missing_jti" });
  revokeToken(req.user.jti, req.user.exp);
  res.json({ status: "success", message: "Logged out successfully" });
});

app.get("/api/auth/me", authenticateJWT, (req, res) => {
  res.json({ authenticated: true, username: req.user.username, token_type: "Bearer" });
});

app.get("/api/health", (req, res) => {
  res.json({ status: "ok", service: "vpn-oauth-server" });
});

app.use((req, res) => {
  res.status(404).json({ error: "not_found" });
});

/* --------------------------------------------------
   Start Server
-------------------------------------------------- */

app.listen(PORT, "0.0.0.0", () => {
  console.log(`VPN OAuth server running on port ${PORT}`);
});
