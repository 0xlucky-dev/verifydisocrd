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
    cluster_id TEXT,
    whitelisted INTEGER DEFAULT 0
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

// Ensure whitelisted column exists (migration for existing DBs)
try { db.exec("ALTER TABLE verified_users ADD COLUMN whitelisted INTEGER DEFAULT 0"); } catch(e) {}

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

function clusterCheck(discordId) {
  // Anti-alt: block ONLY if another account in same cluster already claimed $daily
  // within the cooldown window. Having multiple accounts alone is NOT enough to block.
  const user = db.prepare("SELECT * FROM verified_users WHERE discord_id=?").get(discordId);
  if (!user) {
    // Not verified yet — allow
    return { isAlt: false, otherAccounts: [] };
  }

  // If this user is whitelisted, never block them
  if (user.whitelisted) {
    return { isAlt: false, otherAccounts: [] };
  }

  // Find other accounts with same IP OR same fingerprint (exclude self + whitelisted)
  const others = db.prepare(`
    SELECT discord_id FROM verified_users
    WHERE discord_id != ?
      AND whitelisted = 0
      AND (ip = ? OR fp_hash = ?)
  `).all(discordId, user.ip, user.fp_hash);

  if (others.length === 0) {
    return { isAlt: false, otherAccounts: [] };
  }

  // Only block if any of those other accounts claimed within last 24h
  const window = 24 * 3600;
  const now = Math.floor(Date.now() / 1000);
  const otherIds = others.map(r => r.discord_id);
  const placeholders = otherIds.map(() => '?').join(',');
  const claimed = db.prepare(`
    SELECT discord_id FROM checkin_log
    WHERE discord_id IN (${placeholders})
      AND claimed_at > ?
    ORDER BY claimed_at DESC LIMIT 1
  `).get(...otherIds, now - window);

  if (claimed) {
    return { isAlt: true, claimedBy: claimed.discord_id, otherAccounts: otherIds };
  }

  return { isAlt: false, otherAccounts: otherIds };
}

// Record that a user claimed $daily (used by clusterCheck to detect if alt already claimed)
function recordClaim(discordId) {
  const now = Math.floor(Date.now() / 1000);
  const user = db.prepare("SELECT cluster_id FROM verified_users WHERE discord_id=?").get(discordId);
  const clusterId = user ? user.cluster_id : `unverified::${discordId}`;
  db.prepare(`
    INSERT INTO checkin_log (discord_id, cluster_id, claimed_at, credits_given)
    VALUES (?, ?, ?, 0)
  `).run(discordId, clusterId, now);
}

// Admin: whitelist a user (exempt from cluster check, keeps verify record intact)
function whitelistUser(discordId) {
  const info = db.prepare("UPDATE verified_users SET whitelisted=1 WHERE discord_id=?").run(discordId);
  return { success: info.changes > 0 };
}

// Admin: remove whitelist
function unwhitelistUser(discordId) {
  const info = db.prepare("UPDATE verified_users SET whitelisted=0 WHERE discord_id=?").run(discordId);
  return { success: info.changes > 0 };
}

// Admin: reset cluster — remove the link (set ip/fp to unique values so no match)
// Does NOT delete the record — user doesn't need to re-verify
function resetCluster(discordId) {
  const now = Date.now();
  const info = db.prepare(`
    UPDATE verified_users SET ip = 'reset_' || ?, fp_hash = 'reset_' || ? WHERE discord_id = ?
  `).run(`${discordId}_${now}`, `${discordId}_${now}`, discordId);
  db.prepare("DELETE FROM checkin_log WHERE discord_id=?").run(discordId);
  return { success: info.changes > 0 };
}

// Admin: get cluster info for a user
function getClusterInfo(discordId) {
  const user = db.prepare("SELECT * FROM verified_users WHERE discord_id=?").get(discordId);
  if (!user) return { found: false };
  const others = db.prepare(`
    SELECT discord_id, username, ip, fp_hash, whitelisted FROM verified_users
    WHERE discord_id != ? AND (ip = ? OR fp_hash = ?)
  `).all(discordId, user.ip, user.fp_hash);
  return { found: true, user, clusterMembers: others };
}

module.exports = { saveVerification, getClusterId, getUserInfo, checkAndClaimCheckin, clusterCheck, recordClaim, resetCluster, whitelistUser, unwhitelistUser, getClusterInfo };
