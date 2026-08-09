// NETGUARD - backend, backed by MySQL.
// Receives alerts + traffic samples from the C++ sensor, stores them in
// MySQL, and pushes them live to the dashboard over Socket.io.
//
// THIS VERSION ADDS: Simulated Remediation / Authorize-to-Act.
// High-risk alerts get a recommended action attached (e.g. "Block source
// IP"). NOTHING is ever executed automatically or for real - this backend
// never calls netsh/iptables/any firewall API. The dashboard shows the
// recommendation and waits for you to click "Authorize" or "Dismiss".
// Authorizing only flips a status flag + timestamp in the DB and emits a
// socket event - it is a SIMULATION of taking action, safe to demo live.
//
// AUTH STEP 3: adds bcrypt + POST /api/register.
//
// THIS VERSION ADDS: real persistent "Remember Me", backed by the
// remember_tokens table (selector/validator pattern). Checking
// "remember me" on login or register now survives an 8-hour session
// cookie expiring OR a full backend restart - see the REMEMBER ME
// block below for the actual issuance/validation/revocation logic.
// Nothing else in this file changed - all alert/traffic/session/action
// logic below is identical to the previous working version.

const crypto = require('crypto');
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const pool = require('./db');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

app.use(cors({ origin: true, credentials: true }));
app.use(express.json());

// ---------------------------------------------------------------------
// AUTH SYSTEM - Step 4: Session management
// This is a completely separate thing from the `sessions` MySQL table
// used elsewhere in this file for backend run history. This session
// store lives in server memory only - it tracks "who is logged in right
// now", not backend process lifecycle. Nothing here touches MySQL.
// ---------------------------------------------------------------------
app.use(session({
  secret: 'netguard-demo-secret-change-me', // fine for a local demo; not for production
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    maxAge: 1000 * 60 * 60 * 8 // 8 hour session
  }
}));

// ---------------------------------------------------------------------
// REMEMBER ME - persistent login, backed by the remember_tokens table.
// This is completely separate from express-session above: the 8-hour
// session cookie is "are you logged in right now, this tab"; this
// cookie is "should we silently log you back in if that expires."
//
// Cookie shape sent to the browser: "<selector>:<validator>"
//   - selector: short, public, unique - used to find the row fast with
//     a plain WHERE selector = ? (no secret ever compared in SQL).
//   - validator: long, secret - only its bcrypt hash is ever stored in
//     MySQL (column validator_hash), same approach as password_hash.
// A full dump of remember_tokens therefore can't be used to log in as
// anyone, because the raw validator never touches the database.
// ---------------------------------------------------------------------
const REMEMBER_COOKIE_NAME = 'netguard_remember';
const REMEMBER_DAYS = 30;

// No cookie-parser dependency is installed, so this reads the raw
// "Cookie" request header by hand - just enough to pull out one value.
function getCookie(req, name) {
  const header = req.headers.cookie;
  if (!header) return null;
  const parts = header.split(';');
  for (const part of parts) {
    const eq = part.indexOf('=');
    if (eq === -1) continue;
    const key = part.slice(0, eq).trim();
    if (key === name) return decodeURIComponent(part.slice(eq + 1).trim());
  }
  return null;
}

// Issues a brand-new remember-me token for a user and sets the cookie
// on the response. Called from /api/register and /api/auth/login,
// only when the request body's rememberMe was truthy.
async function issueRememberToken(user, res) {
  const selector = crypto.randomBytes(9).toString('hex');   // 18 chars, fits selector VARCHAR(24)
  const validator = crypto.randomBytes(32).toString('hex'); // secret, only ever hashed in MySQL
  const validatorHash = await bcrypt.hash(validator, 10);

  await pool.query(
    `INSERT INTO remember_tokens (user_id, selector, validator_hash, expires_at)
     VALUES (?, ?, ?, DATE_ADD(NOW(), INTERVAL ${REMEMBER_DAYS} DAY))`,
    [user.id, selector, validatorHash]
  );

  res.cookie(REMEMBER_COOKIE_NAME, `${selector}:${validator}`, {
    httpOnly: true,
    maxAge: 1000 * 60 * 60 * 24 * REMEMBER_DAYS,
    sameSite: 'lax',
    path: '/'
    // no `secure: true` - this demo runs over plain http://localhost
  });

  console.log(`[REMEMBER-ME] Issued token for ${user.username} (30 days)`);
}

// If there's no live session but a valid remember-me cookie, this
// silently re-establishes req.session.user - called from requireAuth,
// requireAdmin, and GET /api/auth/me, so a returning visitor never
// sees the login screen just because their 8-hour session expired.
async function tryRestoreFromRememberCookie(req) {
  if (req.session.user) return; // already logged in, nothing to do

  const cookieVal = getCookie(req, REMEMBER_COOKIE_NAME);
  if (!cookieVal || !cookieVal.includes(':')) return;
  const [selector, validator] = cookieVal.split(':');
  if (!selector || !validator) return;

  try {
    const [rows] = await pool.query('SELECT * FROM remember_tokens WHERE selector = ?', [selector]);
    if (rows.length === 0) return;

    const token = rows[0];
    if (new Date(token.expires_at) < new Date()) {
      // Expired - clean up the stale row so it doesn't linger forever.
      await pool.query('DELETE FROM remember_tokens WHERE id = ?', [token.id]);
      return;
    }

    const validatorMatches = await bcrypt.compare(validator, token.validator_hash);
    if (!validatorMatches) return; // cookie doesn't match this selector's secret - ignore it

    const [userRows] = await pool.query('SELECT id, username, role FROM users WHERE id = ?', [token.user_id]);
    if (userRows.length === 0) return; // user was deleted; ON DELETE CASCADE will have removed the token too

    req.session.user = userRows[0];
    console.log(`[REMEMBER-ME] Silently re-authenticated ${userRows[0].username} from cookie`);
  } catch (err) {
    console.error('Error validating remember-me cookie:', err);
  }
}

app.use(express.static('public')); // serves the dashboard HTML/JS

// ---------------------------------------------------------------------
// AUTH SYSTEM - Step 3: Registration endpoint
// This is the ONLY auth route that exists so far. It does not log
// anyone in (no sessions/cookies yet - that's Step 4). It only creates
// a row in the `users` table with a securely hashed password.
//
// - username/password are required. Self-registration ALWAYS creates a
//   'viewer' account - there is no client-supplied role here, and any
//   'role' field in the request body is ignored outright. No real SOC
//   lets a signup form hand out admin; promoting a user to admin is a
//   separate, out-of-band action (e.g. a direct DB update by an existing
//   administrator), not something exposed on this endpoint.
// - bcrypt.hash(password, 10) turns the plaintext password into a
//   one-way hash before it ever touches the database - the plaintext
//   password is never stored or logged anywhere.
// - If the username is already taken, MySQL's UNIQUE constraint on
//   `users.username` rejects the insert with error code ER_DUP_ENTRY,
//   which we catch and turn into a clean 409 response instead of a
//   crash / raw SQL error leaking to the client.
// ---------------------------------------------------------------------
app.post('/api/register', async (req, res) => {
  try {
    const { username, password, rememberMe } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'username and password are required' });
    }

    const finalRole = 'viewer'; // self-registration can never create an admin
    const password_hash = await bcrypt.hash(password, 10);

    const [result] = await pool.query(
      `INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)`,
      [username, password_hash, finalRole]
    );

    console.log(`[AUTH] New user registered: ${username} (role: ${finalRole})`);

    const newUser = { id: result.insertId, username, role: finalRole };

    if (rememberMe) {
      await issueRememberToken(newUser, res);
    }

    res.status(201).json(newUser);
  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ error: 'That username is already taken' });
    }
    console.error('Error registering user:', err);
    res.status(500).json({ error: 'Failed to register user' });
  }
});

// ---------------------------------------------------------------------
// AUTH SYSTEM - Password reset
// This demo has no SMTP/email service configured, so it can't do a real
// "email you a reset link" flow. What it DOES do for real: confirm the
// username exists, then overwrite that account's password_hash with a
// freshly bcrypt-hashed value of the new password the user typed in.
//
// Be clear with anyone extending this: since there is no email/SMS step
// to prove the requester owns the account, this only verifies a
// username exists, not identity. That's fine for a local training/demo
// box, but a real deployment needs an actual verification channel
// (emailed single-use token, SMS code, etc.) in front of this.
// ---------------------------------------------------------------------
app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const { username, newPassword } = req.body;

    if (!username || !newPassword) {
      return res.status(400).json({ error: 'username and newPassword are required' });
    }
    if (newPassword.length < 6) {
      return res.status(400).json({ error: 'New password must be at least 6 characters' });
    }

    const [rows] = await pool.query('SELECT id FROM users WHERE username = ?', [username]);
    if (rows.length === 0) {
      return res.status(404).json({ error: 'No account found with that username' });
    }

    const password_hash = await bcrypt.hash(newPassword, 10);
    await pool.query('UPDATE users SET password_hash = ? WHERE username = ?', [password_hash, username]);

    console.log(`[AUTH] Password reset for user: ${username}`);
    res.json({ success: true });
  } catch (err) {
    console.error('Error resetting password:', err);
    res.status(500).json({ error: 'Failed to reset password' });
  }
});

// ---------------------------------------------------------------------
// AUTH SYSTEM - Step 4: Login / Me / Logout
// Login checks the password with bcrypt.compare against the stored
// hash, then stores only the safe fields (id, username, role) in the
// session - the password_hash NEVER goes into the session.
// ---------------------------------------------------------------------
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password, rememberMe } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: 'username and password are required' });
    }

    const [rows] = await pool.query('SELECT * FROM users WHERE username = ?', [username]);
    if (rows.length === 0) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    const user = rows[0];
    const passwordMatches = await bcrypt.compare(password, user.password_hash);
    if (!passwordMatches) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    const sessionUser = { id: user.id, username: user.username, role: user.role };
    req.session.user = sessionUser;

    if (rememberMe) {
      await issueRememberToken(sessionUser, res);
    }

    console.log(`[AUTH] User logged in: ${user.username} (role: ${user.role})`);
    res.json(sessionUser);
  } catch (err) {
    console.error('Error logging in:', err);
    res.status(500).json({ error: 'Failed to log in' });
  }
});

// "Who am I" check - the frontend calls this on load to decide whether
// to show the dashboard or bounce to the login screen.
app.get('/api/auth/me', async (req, res) => {
  if (!req.session.user) {
    await tryRestoreFromRememberCookie(req);
  }
  if (!req.session.user) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  res.json(req.session.user);
});

app.post('/api/auth/logout', async (req, res) => {
  const username = req.session.user ? req.session.user.username : 'unknown';

  // Revoke persistent access on THIS device, not just the current tab's
  // session - logging out should mean logged out, even if "remember me"
  // was checked. Deletes the DB row so the cookie (even if it lingers in
  // the browser) can never be validated again.
  const cookieVal = getCookie(req, REMEMBER_COOKIE_NAME);
  if (cookieVal && cookieVal.includes(':')) {
    const [selector] = cookieVal.split(':');
    try {
      await pool.query('DELETE FROM remember_tokens WHERE selector = ?', [selector]);
    } catch (err) {
      console.error('Error revoking remember-me token on logout:', err);
    }
  }
  res.clearCookie(REMEMBER_COOKIE_NAME, { path: '/' });

  req.session.destroy((err) => {
    if (err) {
      console.error('Error destroying session:', err);
      return res.status(500).json({ error: 'Failed to log out' });
    }
    console.log(`[AUTH] User logged out: ${username}`);
    res.json({ success: true });
  });
});

// Static MITRE ATT&CK lookup - unchanged, still just a JS map, not real logic.
const MITRE_MAP = {
  port_scan: { id: 'T1046', name: 'Network Service Discovery' },
  admin_port_access: { id: 'T1021', name: 'Remote Services' },
  large_packet: { id: 'T1499', name: 'Endpoint Denial of Service' },
  syn_flood: { id: 'T1499', name: 'Endpoint Denial of Service' },
  icmp_flood: { id: 'T1046', name: 'Network Service Discovery (Sweep)' },
  stealth_scan_null: { id: 'T1046', name: 'Network Service Discovery (Stealth Scan)' },
  stealth_scan_fin: { id: 'T1046', name: 'Network Service Discovery (Stealth Scan)' },
  stealth_scan_xmas: { id: 'T1046', name: 'Network Service Discovery (Stealth Scan)' },
  brute_force_admin: { id: 'T1110', name: 'Brute Force' },
  dns_tunneling: { id: 'T1071.004', name: 'Application Layer Protocol: DNS' },
  blacklisted_ip: { id: 'T1583', name: 'Acquire Infrastructure' }
};

// ---------------------------------------------------------------------
// Simulated Remediation - recommendation map.
// Only event types worth acting on get a recommendation; low-severity /
// purely informational events (admin_port_access first-touch, large_packet
// anomaly) return null and never show up in the Recommended Actions panel.
// This is intentionally a plain lookup table, not a "smart" engine - easy
// to explain in a viva: "if X pattern fires, Y is the standard textbook
// response, and here it's SIMULATED, not actually executed."
// ---------------------------------------------------------------------
const ACTION_RECOMMENDATIONS = {
  blacklisted_ip: 'Block source IP at firewall — known malicious address',
  brute_force_admin: 'Block source IP and temporarily lock the targeted admin port',
  syn_flood: 'Rate-limit or block source IP — SYN flood mitigation',
  stealth_scan_null: 'Block source IP — stealth scan detected',
  stealth_scan_fin: 'Block source IP — stealth scan detected',
  stealth_scan_xmas: 'Block source IP — stealth scan detected',
  port_scan: 'Block source IP — port scan detected',
  dns_tunneling: 'Flag source IP for deep packet inspection of DNS traffic',
  icmp_flood: 'Rate-limit ICMP traffic from source IP'
};

function computeRecommendedAction(eventType) {
  return ACTION_RECOMMENDATIONS[eventType] || null;
}

// Returns true for LAN/loopback ranges - ip-api.com can't geolocate
// these to a real place, so we skip the lookup entirely for them.
function isPrivateIP(ip) {
  if (!ip) return true;
  if (ip === '127.0.0.1' || ip.startsWith('127.')) return true;
  if (ip.startsWith('10.')) return true;
  if (ip.startsWith('192.168.')) return true;
  const parts = ip.split('.').map(Number);
  if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
  return false;
}

// Free ip-api.com lookup, no key needed. 2s timeout, and ANY failure
// (timeout, bad IP, API down) resolves to {country:null, city:null}
// rather than throwing - a geolocation hiccup should never block an
// alert from being saved.
async function lookupGeo(ip) {
  if (isPrivateIP(ip)) {
    return { country: null, city: null, is_private: true };
  }
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 2000);
    const resp = await fetch(`http://ip-api.com/json/${ip}?fields=status,country,city`, {
      signal: controller.signal
    });
    clearTimeout(timeoutId);
    const data = await resp.json();
    if (data.status === 'success') {
      return { country: data.country || null, city: data.city || null, is_private: false };
    }
    return { country: null, city: null, is_private: false };
  } catch (err) {
    console.error('Geo lookup failed for', ip, '-', err.message);
    return { country: null, city: null, is_private: false };
  }
}

// Turns one MySQL "alerts" row into the JSON shape the dashboard expects.
// Additive: dest_ip, signature, geo, and now `action` sit alongside the
// original fields.
function rowToAlert(row) {
  return {
    id: row.id,
    timestamp: row.created_at,
    source_ip: row.source_ip,
    dest_ip: row.dest_ip || null,
    event_type: row.event_type,
    severity: row.severity,
    message: row.message || '',
    signature: row.signature || null,
    mitre: { id: row.mitre_id, name: row.mitre_name },
    geo: {
      country: row.geo_country || null,
      city: row.geo_city || null,
      is_private: !!row.geo_is_private
    },
    action: {
      recommended: row.action_recommended || null,
      status: row.action_status || 'none',
      authorized_at: row.action_authorized_at || null
    }
  };
}

// Guards dashboard-data routes so they require a logged-in session.
// The sensor's own POST /api/alerts and POST /api/traffic are left
// open (the C++ sensor doesn't log in) - only the DASHBOARD-facing
// GET routes are protected here.
async function requireAuth(req, res, next) {
  if (!req.session.user) {
    await tryRestoreFromRememberCookie(req);
  }
  if (!req.session.user) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  next();
}

// ---------------------------------------------------------------------
// RBAC - actually enforced (not just a column that sits unused).
// Any authenticated user (admin or viewer) can VIEW alerts, traffic,
// stats, etc. via requireAuth above. But taking a remediation action
// (authorize/dismiss a recommended response) is a real decision with
// consequences in a real deployment, so only 'admin' role accounts can
// do it. Viewers can see the recommendation and its status, but the
// action buttons themselves are gated here at the API level - this is
// the actual access-control boundary, not just something implied by
// the marketing copy on the login page.
// ---------------------------------------------------------------------
async function requireAdmin(req, res, next) {
  if (!req.session.user) {
    await tryRestoreFromRememberCookie(req);
  }
  if (!req.session.user) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  if (req.session.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin role required to authorize or dismiss remediation actions' });
  }
  next();
}

// ---------------------------------------------------------------------
// "Clear" cursors - schema update 6 (user_clears table).
//
// Clicking Clear on Recent Activity / Live Alert Feed / Live Traffic
// Monitor does NOT delete anything from `alerts` or `traffic_samples`.
// It only records, for the logged-in user, "I cleared this view at
// this moment" - a timestamp cursor. index.html then hides anything
// timestamped at or before that cursor on that view, on every load,
// until a genuinely newer item arrives. Other users are unaffected -
// each user's cursor is their own row in user_clears.
//
// VIEW_NAMES mirrors the enum in the user_clears table exactly - kept
// as a whitelist here so a typo'd/unexpected `view` value from the
// client can never reach the SQL query.
// ---------------------------------------------------------------------
const VIEW_NAMES = ['recent_activity', 'live_alerts', 'traffic'];

// Frontend calls this once right after login/on page load, to find out
// where (if anywhere) each of this user's three cursors currently sits.
app.get('/api/clears', requireAuth, async (req, res) => {
  try {
    const [rows] = await pool.query(
      'SELECT view_name, cleared_at FROM user_clears WHERE user_id = ?',
      [req.session.user.id]
    );

    // Shape as { recent_activity: <timestamp or null>, live_alerts: ..., traffic: ... }
    // so the frontend never has to search an array to find one view's cursor.
    const cursors = { recent_activity: null, live_alerts: null, traffic: null };
    for (const row of rows) {
      cursors[row.view_name] = row.cleared_at;
    }
    res.json(cursors);
  } catch (err) {
    console.error('Error fetching clear cursors:', err);
    res.status(500).json({ error: 'Failed to fetch clear cursors' });
  }
});

// Frontend calls this when a Clear button is clicked. Body: { view: 'live_alerts' }
// (or 'recent_activity' / 'traffic'). Moves that view's cursor to "now" for
// this user - INSERT ... ON DUPLICATE KEY UPDATE means each user has at most
// one row per view (per the UNIQUE KEY in the table), so clicking Clear again
// just moves the existing cursor forward rather than piling up rows.
app.post('/api/clears', requireAuth, async (req, res) => {
  try {
    const { view } = req.body;
    if (!VIEW_NAMES.includes(view)) {
      return res.status(400).json({ error: `view must be one of: ${VIEW_NAMES.join(', ')}` });
    }

    await pool.query(
      `INSERT INTO user_clears (user_id, view_name, cleared_at)
       VALUES (?, ?, NOW())
       ON DUPLICATE KEY UPDATE cleared_at = NOW()`,
      [req.session.user.id, view]
    );

    const [rows] = await pool.query(
      'SELECT cleared_at FROM user_clears WHERE user_id = ? AND view_name = ?',
      [req.session.user.id, view]
    );

    console.log(`[CLEAR] ${req.session.user.username} cleared "${view}"`);
    res.json({ view, cleared_at: rows[0].cleared_at });
  } catch (err) {
    console.error('Error saving clear cursor:', err);
    res.status(500).json({ error: 'Failed to save clear cursor' });
  }
});

// Sensor posts alerts here
app.post('/api/alerts', async (req, res) => {
  try {
    const { source_ip, dest_ip, event_type, severity, message, signature } = req.body;
    if (!source_ip || !event_type) {
      return res.status(400).json({ error: 'source_ip and event_type are required' });
    }

    const mitre = MITRE_MAP[event_type] || { id: 'N/A', name: 'Unmapped' };
    const sev = severity || 'medium';

    // Geo lookup runs before the INSERT so we can store the result,
    // not just return it - fails gracefully to nulls, never blocks the alert.
    const geo = await lookupGeo(source_ip);

    // Recommended action (if any) is computed once at insert time and
    // stored - status starts 'pending' if there IS a recommendation,
    // otherwise 'none'. Nothing is executed here, only recommended.
    const recommendedAction = computeRecommendedAction(event_type);
    const actionStatus = recommendedAction ? 'pending' : 'none';

    const [result] = await pool.query(
      `INSERT INTO alerts
        (source_ip, dest_ip, event_type, severity, message, signature,
         action_recommended, action_status,
         mitre_id, mitre_name, geo_country, geo_city, geo_is_private)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        source_ip, dest_ip || null, event_type, sev, message || '', signature || null,
        recommendedAction, actionStatus,
        mitre.id, mitre.name, geo.country, geo.city, geo.is_private
      ]
    );

    const [rows] = await pool.query('SELECT * FROM alerts WHERE id = ?', [result.insertId]);
    const alert = rowToAlert(rows[0]);

    io.emit('new_alert', alert); // push live to dashboard
    console.log(`[ALERT RECEIVED] ${alert.event_type} from ${alert.source_ip}`);
    res.status(201).json(alert);
  } catch (err) {
    console.error('Error saving alert:', err);
    res.status(500).json({ error: 'Failed to save alert' });
  }
});

// Dashboard fetches alert history on load
app.get('/api/alerts', requireAuth, async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT * FROM alerts ORDER BY created_at DESC');
    res.json(rows.map(rowToAlert));
  } catch (err) {
    console.error('Error fetching alerts:', err);
    res.status(500).json({ error: 'Failed to fetch alerts' });
  }
});

// ---------------------------------------------------------------------
// Simulated Remediation endpoints.
// These NEVER touch a real firewall, router, or network device. They
// only update action_status/action_authorized_at in MySQL and notify
// the dashboard over Socket.io. Authorizing = "yes, if this were wired
// to a real firewall, fire it now" - it is a recorded human decision,
// not an executed command.
// ---------------------------------------------------------------------
app.post('/api/alerts/:id/authorize', requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const [rows] = await pool.query('SELECT * FROM alerts WHERE id = ?', [id]);
    if (rows.length === 0) return res.status(404).json({ error: 'Alert not found' });
    if (!rows[0].action_recommended) {
      return res.status(400).json({ error: 'This alert has no recommended action to authorize' });
    }

    await pool.query(
      `UPDATE alerts SET action_status = 'authorized', action_authorized_at = NOW() WHERE id = ?`,
      [id]
    );

    const [updatedRows] = await pool.query('SELECT * FROM alerts WHERE id = ?', [id]);
    const alert = rowToAlert(updatedRows[0]);

    // Console line makes the "simulated, not real" boundary explicit and
    // demoable - this is the only place that "acts", and it only logs.
    console.log(`[SIMULATED ACTION] Would ${alert.action.recommended.toLowerCase()} for ${alert.source_ip} (alert #${id}) - NOT actually executed.`);

    io.emit('alert_action_updated', alert);
    res.json(alert);
  } catch (err) {
    console.error('Error authorizing action:', err);
    res.status(500).json({ error: 'Failed to authorize action' });
  }
});

app.post('/api/alerts/:id/dismiss', requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const [rows] = await pool.query('SELECT * FROM alerts WHERE id = ?', [id]);
    if (rows.length === 0) return res.status(404).json({ error: 'Alert not found' });

    await pool.query(`UPDATE alerts SET action_status = 'dismissed' WHERE id = ?`, [id]);

    const [updatedRows] = await pool.query('SELECT * FROM alerts WHERE id = ?', [id]);
    const alert = rowToAlert(updatedRows[0]);

    io.emit('alert_action_updated', alert);
    res.json(alert);
  } catch (err) {
    console.error('Error dismissing action:', err);
    res.status(500).json({ error: 'Failed to dismiss action' });
  }
});

// --- Normal traffic samples - NOT alerts, just a "sensor is alive" feed ---
const MAX_TRAFFIC_SAMPLES = 30; // keep the dashboard list short and current

app.post('/api/traffic', async (req, res) => {
  try {
    const { source_ip, dst_port, bytes } = req.body;
    if (!source_ip) return res.status(400).json({ error: 'source_ip is required' });

    const [result] = await pool.query(
      `INSERT INTO traffic_samples (source_ip, dst_port, bytes) VALUES (?, ?, ?)`,
      [source_ip, dst_port || 0, bytes || 0]
    );

    const [rows] = await pool.query('SELECT * FROM traffic_samples WHERE id = ?', [result.insertId]);
    const row = rows[0];
    const sample = {
      timestamp: row.created_at,
      source_ip: row.source_ip,
      dst_port: row.dst_port,
      bytes: row.bytes
    };

    io.emit('traffic_sample', sample); // separate socket event from alerts
    res.status(201).json(sample);
  } catch (err) {
    console.error('Error saving traffic sample:', err);
    res.status(500).json({ error: 'Failed to save traffic sample' });
  }
});

app.get('/api/traffic', requireAuth, async (req, res) => {
  try {
    const [rows] = await pool.query(
      'SELECT * FROM traffic_samples ORDER BY created_at DESC LIMIT ?',
      [MAX_TRAFFIC_SAMPLES]
    );
    res.json(rows.map(row => ({
      timestamp: row.created_at,
      source_ip: row.source_ip,
      dst_port: row.dst_port,
      bytes: row.bytes
    })));
  } catch (err) {
    console.error('Error fetching traffic samples:', err);
    res.status(500).json({ error: 'Failed to fetch traffic samples' });
  }
});

// Simple counts for the chart
app.get('/api/stats', requireAuth, async (req, res) => {
  try {
    const [rows] = await pool.query(
      'SELECT event_type, COUNT(*) AS count FROM alerts GROUP BY event_type'
    );
    const counts = {};
    for (const r of rows) counts[r.event_type] = r.count;
    res.json(counts);
  } catch (err) {
    console.error('Error fetching stats:', err);
    res.status(500).json({ error: 'Failed to fetch stats' });
  }
});

// ---------------------------------------------------------------------
// Session lifecycle endpoints.
// A "session" here means one continuous run of THIS Node process - it
// starts the instant this file boots and ends only when the process is
// stopped with Ctrl+C (SIGINT), never on a browser refresh. See
// startSession()/endSession() further below for where the actual
// insert/update happens.
// ---------------------------------------------------------------------
app.get('/api/session/current', requireAuth, async (req, res) => {
  try {
    if (!currentSessionId) {
      return res.status(503).json({ error: 'Session not initialized yet - try again shortly' });
    }
    const [rows] = await pool.query('SELECT * FROM sessions WHERE id = ?', [currentSessionId]);
    if (rows.length === 0) return res.status(404).json({ error: 'Current session row not found' });
    const row = rows[0];
    res.json({
      id: row.id,
      started_at: row.started_at,
      ended_at: row.ended_at,
      is_active: row.ended_at === null
    });
  } catch (err) {
    console.error('Error fetching current session:', err);
    res.status(500).json({ error: 'Failed to fetch current session' });
  }
});

app.get('/api/sessions', requireAuth, async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT * FROM sessions ORDER BY started_at DESC');

    // total_alerts/high_severity_count are only ever WRITTEN once, inside
    // endSession() below - which only runs on a clean Ctrl+C shutdown. So
    // for whichever row is the currently-running session, those columns
    // are still NULL in MySQL itself, no matter how many alerts have come
    // in - that's why the dashboard only showed a count after a restart.
    // Fix: compute that one row's counts live, on every request, the same
    // way endSession() eventually will. Deliberately scoped to
    // `row.id === currentSessionId` (not just "any row with ended_at IS
    // NULL") - a crashed/never-cleanly-closed old session also has
    // ended_at NULL, and re-querying alerts from ITS started_at onward
    // would incorrectly include every alert generated by every session
    // since, growing forever. Only the actual live session gets this.
    for (const row of rows) {
      if (row.id === currentSessionId && row.ended_at === null) {
        const [countRows] = await pool.query(
          `SELECT COUNT(*) AS total,
                  SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) AS highCount
           FROM alerts WHERE created_at >= ?`,
          [row.started_at]
        );
        row.total_alerts = countRows[0].total || 0;
        row.high_severity_count = countRows[0].highCount || 0;
      }
    }

    res.json(rows);
  } catch (err) {
    console.error('Error fetching session history:', err);
    res.status(500).json({ error: 'Failed to fetch session history' });
  }
});

io.on('connection', (socket) => {
  console.log('Dashboard connected:', socket.id);
});

// ---------------------------------------------------------------------
// Session lifecycle - the actual start/end logic.
// currentSessionId is set once, right when this process boots, and
// stays fixed for the entire life of this process. It has nothing to do
// with browser tabs/refreshes - only this variable existing means "this
// backend process is the one currently running."
// ---------------------------------------------------------------------
let currentSessionId = null;

async function startSession() {
  const [result] = await pool.query('INSERT INTO sessions (started_at) VALUES (NOW())');
  currentSessionId = result.insertId;
  console.log(`[SESSION] Started session #${currentSessionId}`);
}

// Called only on a clean shutdown (Ctrl+C). Computes how many alerts
// happened during this session's window (started_at -> now) and writes
// the final summary + ended_at into the sessions row. If the process is
// killed forcefully instead (crash, Task Manager "End Task"), this never
// runs - the row is deliberately left with ended_at = NULL, which the
// dashboard's Session Log page will show as "did not shut down cleanly."
async function endSession() {
  if (!currentSessionId) return;
  try {
    const [sessionRows] = await pool.query('SELECT started_at FROM sessions WHERE id = ?', [currentSessionId]);
    if (sessionRows.length === 0) return;
    const startedAt = sessionRows[0].started_at;

    const [countRows] = await pool.query(
      `SELECT COUNT(*) AS total,
              SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) AS highCount
       FROM alerts WHERE created_at >= ?`,
      [startedAt]
    );
    const total = countRows[0].total || 0;
    const highCount = countRows[0].highCount || 0;

    await pool.query(
      `UPDATE sessions SET ended_at = NOW(), total_alerts = ?, high_severity_count = ? WHERE id = ?`,
      [total, highCount, currentSessionId]
    );
    console.log(`[SESSION] Session #${currentSessionId} ended - ${total} alerts (${highCount} high severity).`);
  } catch (err) {
    console.error('Error recording session end:', err);
  }
}

// Ctrl+C in the terminal sends SIGINT - this is the ONLY thing that ends
// a session. Closing the browser tab or refreshing it does nothing here.
process.on('SIGINT', async () => {
  console.log('\n[NETGUARD] Ctrl+C received - closing out this session...');
  await endSession();
  process.exit(0);
});

const PORT = 8000;

(async () => {
  await startSession();
  server.listen(PORT, '0.0.0.0', () => {
    console.log(`NETGUARD backend running on http://0.0.0.0:${PORT}`);
    console.log(`Dashboard: http://localhost:${PORT}`);
  });
})();
