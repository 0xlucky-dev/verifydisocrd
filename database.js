const Database = require("better-sqlite3");
const path = require("path");

const db = new Database(path.join(__dirname, "verify.db"));

db.exec(`
  CREATE TABLE IF NOT EXISTS verified_users (
    discord_id TEXT PRIMARY KEY,
    username TEXT,
    ip TEXT,
    fp_hash TEXT,
    account_created_at INTEGER,
    verified_at INTEGER,
    cluster_id TEXT
  );
  CREATE TABLE IF NOT EXISTS checkin_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    discord_id TEXT,
    cluster_id TEXT,
    claimed_at INTEGER,
    credits_given INTEGER
  );
  CREATE INDEX IF NOT EXISTS idx_cluster ON verified_users(cluster_id);
  CREATE INDEX IF NOT EXISTS idx_checkin_cluster ON checkin_log(cluster_id);
`);

function makeClusterId(ip, fpHash) {
  return `${ip}::${fpHash}`;
}

function saveVerification(discordId, username, ip, fpHash, accountCreatedAt) {
  const clusterId = makeClusterId(ip, fpHash);
  const now = Math.floor(Date.now() / 1000);
  db.prepare(`
    INSERT INTO verified_users (discord_id, username, ip, fp_hash, account_created_at, verified_at, cluster_id)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(discord_id) DO UPDATE SET
      username=excluded.username, ip=excluded.ip, fp_hash=excluded.fp_hash,
      verified_at=excluded.verified_at, cluster_id=excluded.cluster_id
  `).run(discordId, username, ip, fpHash, accountCreatedAt, now, clusterId);
  return clusterId;
}

function getClusterId(discordId) {
  const row = db.prepare("SELECT cluster_id FROM verified_users WHERE discord_id=?").get(discordId);
  return row ? row.cluster_id : null;
}

function getUserInfo(discordId) {
  return db.prepare("SELECT * FROM verified_users WHERE discord_id=?").get(discordId) || null;
}

function checkAndClaimCheckin(discordId, credits, cooldownHours = 24) {
  const now = Math.floor(Date.now() / 1000);
  const window = cooldownHours * 3600;

  // Get this user's verification info
  const user = db.prepare("SELECT * FROM verified_users WHERE discord_id=?").get(discordId);

  if (user) {
    // Check if ANYONE with same IP OR same fingerprint already claimed today
    const row = db.prepare(`
      SELECT cl.discord_id, cl.claimed_at FROM checkin_log cl
      JOIN verified_users vu ON cl.discord_id = vu.discord_id
      WHERE cl.claimed_at > ?
        AND cl.discord_id != ?
        AND (vu.ip = ? OR vu.fp_hash = ?)
      ORDER BY cl.claimed_at DESC LIMIT 1
    `).get(now - window, discordId, user.ip, user.fp_hash);

    if (row) {
      const hoursRemaining = (row.claimed_at + window - now) / 3600;
      return { allowed: false, blockingId: row.discord_id, hoursRemaining: Math.max(0, hoursRemaining) };
    }

    // Check if THIS user already claimed
    const self = db.prepare(`
      SELECT claimed_at FROM checkin_log
      WHERE discord_id = ? AND claimed_at > ?
      ORDER BY claimed_at DESC LIMIT 1
    `).get(discordId, now - window);

    if (self) {
      const hoursRemaining = (self.claimed_at + window - now) / 3600;
      return { allowed: false, blockingId: discordId, hoursRemaining: Math.max(0, hoursRemaining) };
    }
  } else {
    // Not verified — check by discord_id only
    const self = db.prepare(`
      SELECT claimed_at FROM checkin_log
      WHERE discord_id = ? AND claimed_at > ?
      ORDER BY claimed_at DESC LIMIT 1
    `).get(discordId, now - window);

    if (self) {
      const hoursRemaining = (self.claimed_at + window - now) / 3600;
      return { allowed: false, blockingId: discordId, hoursRemaining: Math.max(0, hoursRemaining) };
    }
  }

  // Allowed — record
  const clusterId = user ? user.cluster_id : `unverified::${discordId}`;
  db.prepare(`
    INSERT INTO checkin_log (discord_id, cluster_id, claimed_at, credits_given)
    VALUES (?, ?, ?, ?)
  `).run(discordId, clusterId, now, credits);

  return { allowed: true, blockingId: null, hoursRemaining: 0 };
}

module.exports = { saveVerification, getClusterId, getUserInfo, checkAndClaimCheckin };
