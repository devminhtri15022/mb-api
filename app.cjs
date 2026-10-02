const express = require("express");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const moment = require("moment-timezone");
const { v4: uuidv4 } = require("uuid");

const PORT = Number(process.env.PORT || 8787);
const TIME_ZONE = "Asia/Ho_Chi_Minh";
const DATA_DIR = path.join(__dirname, "data");
const STORE_PATH = path.join(DATA_DIR, "accounts.json");
const KEY_FILE = path.join(DATA_DIR, ".master_key");

function loadOrCreateMasterKey() {
  if (process.env.MASTER_KEY && process.env.MASTER_KEY.length >= 32) return process.env.MASTER_KEY;
  try { if (fs.existsSync(KEY_FILE)) { const k = fs.readFileSync(KEY_FILE, "utf8").trim(); if (k.length >= 32) return k; } } catch {}
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
  const k = crypto.randomBytes(32).toString("hex");
  fs.writeFileSync(KEY_FILE, k, { mode: 0o600 });
  console.log("🔑 MASTER_KEY:", k);
  return k;
}

const MASTER_KEY = loadOrCreateMasterKey();

function keyBuf() { return crypto.createHash("sha256").update(MASTER_KEY).digest(); }
function encrypt(plain) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", keyBuf(), iv);
  const enc = Buffer.concat([cipher.update(String(plain), "utf8"), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), enc]).toString("base64");
}
function decrypt(blob) {
  const buf = Buffer.from(String(blob), "base64");
  const decipher = crypto.createDecipheriv("aes-256-gcm", keyBuf(), buf.subarray(0, 12));
  decipher.setAuthTag(buf.subarray(12, 28));
  return Buffer.concat([decipher.update(buf.subarray(28)), decipher.final()]).toString("utf8");
}
function makeToken() { return crypto.randomBytes(24).toString("hex"); }

function ensureStore() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
  if (!fs.existsSync(STORE_PATH)) fs.writeFileSync(STORE_PATH, "{}");
}
function loadStore() { ensureStore(); try { return JSON.parse(fs.readFileSync(STORE_PATH, "utf8") || "{}"); } catch { return {}; } }
function saveStore(obj) { ensureStore(); const tmp = STORE_PATH + ".tmp"; fs.writeFileSync(tmp, JSON.stringify(obj, null, 2)); fs.renameSync(tmp, STORE_PATH); }

const hits = new Map();
function rateLimit(key, max, windowMs) {
  const now = Date.now();
  const arr = (hits.get(key) || []).filter((t) => now - t < windowMs);
  if (arr.length >= max) return false;
  arr.push(now); hits.set(key, arr); return true;
}

const sessionCache = new Map();
const SESSION_TTL = 8 * 60 * 1000;
let MBClass = null;

async function getMBClass() {
  if (MBClass) return MBClass;
  const mod = await import("mbbank");
  MBClass = mod.MB || mod.default?.MB || mod.default;
  return MBClass;
}

async function getClient(token, account) {
  const cached = sessionCache.get(token);
  if (cached && Date.now() - cached.at < SESSION_TTL) return cached.mb;
  const MB = await getMBClass();
  const mb = new MB({ username: account.username, password: decrypt(account.passwordEnc), preferredOCRMethod: "default", saveWasm: true });
  await mb.login();
  sessionCache.set(token, { mb, at: Date.now() });
  return mb;
}

function normalizeTx(tx) {
  const credit = Number(String(tx.creditAmount ?? "0").replace(/,/g, "").replace(/\s/g, "") || 0);
  return {
    tranId: String(tx.refNo || tx.tranId || `${tx.transactionDate}-${tx.creditAmount}-${tx.transactionDesc}`),
    creditAmount: credit > 0 ? credit : 0,
    description: String(tx.transactionDesc || tx.description || ""),
    transactionDate: tx.transactionDate || tx.postDate || "",
    debitAmount: Number(String(tx.debitAmount ?? "0").replace(/,/g, "") || 0),
  };
}

const app = express();
app.use(express.json({ limit: "32kb" }));
app.use(express.urlencoded({ extended: true }));

app.get("/health", (_req, res) => res.json({ ok: true, ts: Date.now() }));

app.get("/", (_req, res) => {
  res.send(`<!DOCTYPE html><html><body style="font-family:sans-serif;background:#0f172a;color:#fff;display:flex;justify-content:center;align-items:center;height:100vh"><div style="text-align:center"><h1 style="color:#22d3ee">🏦 MB Checkbank API - Running</h1><p style="color:#4ade80">Sẵn sàng nhận lệnh từ NTMT Studio</p></div></body></html>`);
});

app.post("/register", async (req, res) => {
  const ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress || "ip";
  if (!rateLimit(`reg:${ip}`, 10, 15 * 60 * 1000)) return res.status(429).json({ ok: false, error: "Quá nhiều lần, thử lại sau 15 phút" });
  const username = String(req.body.username || "").trim();
  const password = String(req.body.password || "").trim();
  const accountNo = String(req.body.accountNo || "").trim();
  const label = String(req.body.label || "").trim().slice(0, 40);

  if (!/^\d{8,15}$/.test(username)) return res.status(400).json({ ok: false, error: "Username (SĐT MB) không hợp lệ" });
  if (password.length < 4 || password.length > 64) return res.status(400).json({ ok: false, error: "Password không hợp lệ" });
  if (!/^\d{6,20}$/.test(accountNo)) return res.status(400).json({ ok: false, error: "Số tài khoản không hợp lệ" });

  try {
    const MB = await getMBClass();
    const mb = new MB({ username, password, preferredOCRMethod: "default", saveWasm: true });
    await mb.login();
  } catch (e) { 
    return res.status(400).json({ ok: false, error: "Đăng nhập MB thất bại: " + (e?.message || String(e)) }); 
  }

  const token = makeToken();
  const store = loadStore();
  store[token] = { id: uuidv4(), label: label || username, username, accountNo, passwordEnc: encrypt(password), preferredOCRMethod: "default", createdAt: Date.now(), lastUsedAt: null };
  saveStore(store);

  const base = `${req.protocol}://${req.get("host")}`;
  return res.json({ 
    ok: true, 
    token, 
    endpoints: { 
      history: `${base}/api/history/${token}?days=1`, 
      balance: `${base}/api/balance/${token}`, 
      status: `${base}/api/status/${token}` 
    } 
  });
});

app.get("/api/history/:token", async (req, res) => {
  const token = String(req.params.token || "");
  const store = loadStore(); const acc = store[token];
  if (!acc) return res.status(404).json({ ok: false, error: "Token không tồn tại" });
  const days = Math.min(7, Math.max(1, Number(req.query.days) || 1));
  try {
    const mb = await getClient(token, acc);
    const to = moment().tz(TIME_ZONE); const from = to.clone().subtract(days, "days");
    const list = await mb.getTransactionsHistory({ accountNumber: acc.accountNo, fromDate: from.format("DD/MM/YYYY"), toDate: to.format("DD/MM/YYYY") });
    const TranList = (Array.isArray(list) ? list : []).map(normalizeTx).map((t) => ({ 
      tranId: t.tranId, 
      creditAmount: t.creditAmount, 
      debitAmount: t.debitAmount,
      description: t.description, 
      transactionDate: t.transactionDate 
    }));
    acc.lastUsedAt = Date.now(); saveStore(store);
    return res.json({ ok: true, TranList });
  } catch (e) { 
    sessionCache.delete(token); 
    return res.status(500).json({ ok: false, error: e?.message || String(e) }); 
  }
});

app.get("/api/balance/:token", async (req, res) => {
  const token = String(req.params.token || "");
  const store = loadStore(); const acc = store[token];
  if (!acc) return res.status(404).json({ ok: false, error: "Token không tồn tại" });
  try {
    const mb = await getClient(token, acc);
    const balance = await mb.getBalance();
    return res.json({ ok: true, accountNo: acc.accountNo, totalBalance: balance?.totalBalance ?? null });
  } catch (e) { 
    sessionCache.delete(token); 
    return res.status(500).json({ ok: false, error: e?.message || String(e) }); 
  }
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`===========================================`);
  console.log(`🚀 MB Checkbank API đã chạy tại PORT: ${PORT}`);
  console.log(`   Link test: http://localhost:${PORT}/health`);
  console.log(`===========================================`);
});
