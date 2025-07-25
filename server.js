/*
 * Simple When2Meet‑like scheduling server.
 *
 * This server implements a basic event scheduling application inspired by
 * the popular When2Meet tool. It allows users to register, login, create
 * events and submit their availability for specific time slots. When
 * viewing an event, participants can see the combined availability
 * distribution and click individual cells to view which users selected
 * that slot. All data is persisted into a JSON file on disk.
 *
 * The implementation avoids external dependencies (such as Express) and
 * builds upon Node's built‑in `http` and `fs` modules. It manages
 * sessions using randomly generated cookies and stores persistent data in
 * a simple JSON structure. Passwords are salted and hashed using the
 * built‑in crypto module.
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const url = require('url');
const crypto = require('crypto');
const querystring = require('querystring');

// Path to persistent data store. On startup we load this file (if it
// exists). Any changes to users, events or availabilities are flushed to
// disk immediately after the modification. Persisting to a flat file is
// sufficient for demonstration purposes; a production system would
// likely employ a database.
const DATA_PATH = path.join(__dirname, 'data.json');

// In‑memory representation of our application state.
let data = {
  users: [],       // { id, username, salt, passwordHash }
  events: [],      // { id, title, startISO, endISO, slotMinutes, ownerId }
  availability: [] // { eventId, userId, slots: [slotIndex, ...] }
};

// Load persistent data if available
function loadData() {
  try {
    const raw = fs.readFileSync(DATA_PATH, 'utf8');
    data = JSON.parse(raw);
  } catch (e) {
    // File does not exist or cannot be parsed; start fresh
    console.log('Starting with empty data store');
  }
}

// Persist current state to disk
function saveData() {
  fs.writeFileSync(DATA_PATH, JSON.stringify(data, null, 2), 'utf8');
}

// Session management. We store active sessions in memory keyed by a
// randomly generated session ID. Each session contains the associated
// userId and an expiration timestamp. For simplicity sessions live for
// one day from creation. When verifying a session we check that it
// hasn't expired; stale sessions are removed.
const sessions = {};
const SESSION_TTL_MS = 24 * 60 * 60 * 1000; // 1 day

function createSession(userId) {
  const sid = crypto.randomBytes(16).toString('hex');
  sessions[sid] = { userId, expires: Date.now() + SESSION_TTL_MS };
  return sid;
}

function getSession(req) {
  const cookie = req.headers.cookie;
  if (!cookie) return null;
  const parts = cookie.split(';').map(c => c.trim());
  for (const part of parts) {
    if (part.startsWith('sessionId=')) {
      const sid = part.substring('sessionId='.length);
      const session = sessions[sid];
      if (session) {
        if (Date.now() > session.expires) {
          // Session expired; remove
          delete sessions[sid];
          return null;
        }
        return { id: sid, ...session };
      }
    }
  }
  return null;
}

function destroySession(sid) {
  delete sessions[sid];
}

// Helper: generate salt and hash password using PBKDF2
function hashPassword(password, salt = null) {
  if (!salt) {
    salt = crypto.randomBytes(16).toString('hex');
  }
  const hash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha256').toString('hex');
  return { salt, hash };
}

// Helper: serve static files from the public directory. If the file
// doesn't exist, return false so that the caller can handle 404.
function serveStatic(req, res) {
  let pathname = url.parse(req.url).pathname;
  if (pathname === '/') {
    pathname = '/index.html';
  }
  const filePath = path.join(__dirname, 'public', pathname);
  if (!filePath.startsWith(path.join(__dirname, 'public'))) {
    // Prevent directory traversal
    return false;
  }
  try {
    const stat = fs.statSync(filePath);
    if (stat.isFile()) {
      const ext = path.extname(filePath).toLowerCase();
      const mimeTypes = {
        '.html': 'text/html',
        '.js': 'application/javascript',
        '.css': 'text/css',
        '.json': 'application/json',
        '.png': 'image/png',
        '.jpg': 'image/jpeg',
        '.jpeg': 'image/jpeg',
        '.svg': 'image/svg+xml',
        '.ico': 'image/x-icon'
      };
      const mime = mimeTypes[ext] || 'application/octet-stream';
      res.writeHead(200, { 'Content-Type': mime });
      fs.createReadStream(filePath).pipe(res);
      return true;
    }
  } catch (e) {
    // Not found
  }
  return false;
}

// Helper to parse request body. Supports JSON and URL‑encoded forms.
function parseBody(req, callback) {
  let body = '';
  req.on('data', chunk => {
    body += chunk.toString();
    // Limit body size to 1MB
    if (body.length > 1e6) req.connection.destroy();
  });
  req.on('end', () => {
    const contentType = req.headers['content-type'] || '';
    if (contentType.includes('application/json')) {
      try {
        const parsed = JSON.parse(body || '{}');
        callback(null, parsed);
      } catch (e) {
        callback(new Error('Invalid JSON'));
      }
    } else if (contentType.includes('application/x-www-form-urlencoded')) {
      callback(null, querystring.parse(body));
    } else {
      callback(null, {});
    }
  });
}

// Retrieve user by username
function findUserByUsername(username) {
  return data.users.find(u => u.username === username);
}

// Create new user
function createUser(username, password) {
  const { salt, hash } = hashPassword(password);
  const id = data.users.reduce((max, u) => Math.max(max, u.id), 0) + 1;
  const user = { id, username, salt, passwordHash: hash };
  data.users.push(user);
  saveData();
  return user;
}

// Verify password
function verifyPassword(user, password) {
  const { hash } = hashPassword(password, user.salt);
  return hash === user.passwordHash;
}

// Create event
function createEvent(title, startISO, endISO, slotMinutes, ownerId) {
  const id = data.events.reduce((max, e) => Math.max(max, e.id), 0) + 1;
  const event = { id, title, startISO, endISO, slotMinutes, ownerId };
  data.events.push(event);
  saveData();
  return event;
}

// Find event by id
function findEventById(id) {
  return data.events.find(e => e.id === id);
}

// Get or create availability record for given user and event
function getAvailabilityRecord(eventId, userId, createIfMissing = false) {
  let rec = data.availability.find(a => a.eventId === eventId && a.userId === userId);
  if (!rec && createIfMissing) {
    rec = { eventId, userId, slots: [] };
    data.availability.push(rec);
  }
  return rec;
}

// Build aggregated availability for an event. Returns an object mapping
// slotIndex to { count, names }. Also returns max count for scaling.
function buildAggregatedAvailability(eventId) {
  const result = {};
  let maxCount = 0;
  for (const rec of data.availability) {
    if (rec.eventId !== eventId) continue;
    const user = data.users.find(u => u.id === rec.userId);
    const username = user ? user.username : 'Unknown';
    for (const slot of rec.slots) {
      if (!result[slot]) result[slot] = { count: 0, names: [] };
      result[slot].count += 1;
      result[slot].names.push(username);
      if (result[slot].count > maxCount) maxCount = result[slot].count;
    }
  }
  return { aggregated: result, maxCount };
}

// HTTP request handler
function handleRequest(req, res) {
  const parsedUrl = url.parse(req.url, true);
  const pathname = parsedUrl.pathname;

  // Attempt to serve static content from /public
  if (req.method === 'GET' && serveStatic(req, res)) {
    return;
  }

  // API routes start with /api
  if (pathname.startsWith('/api')) {
    // Parse session for every API request
    const session = getSession(req);
      // Endpoint to retrieve current user info
      if (pathname === '/api/me' && req.method === 'GET') {
        if (!session) return sendJSON(res, 200, { user: null });
        const user = data.users.find(u => u.id === session.userId);
        return sendJSON(res, 200, { user: user ? { id: user.id, username: user.username } : null });
      }
    if (pathname === '/api/register' && req.method === 'POST') {
      return parseBody(req, (err, body) => {
        if (err) return sendJSON(res, 400, { error: 'Invalid request body' });
        const { username, password } = body;
        if (!username || !password) {
          return sendJSON(res, 400, { error: 'Missing username or password' });
        }
        if (findUserByUsername(username)) {
          return sendJSON(res, 400, { error: 'User already exists' });
        }
        const user = createUser(username, password);
        const sid = createSession(user.id);
        setSessionCookie(res, sid);
        return sendJSON(res, 200, { ok: true, user: { id: user.id, username: user.username } });
      });
    }
    if (pathname === '/api/login' && req.method === 'POST') {
      return parseBody(req, (err, body) => {
        if (err) return sendJSON(res, 400, { error: 'Invalid request body' });
        const { username, password } = body;
        if (!username || !password) return sendJSON(res, 400, { error: 'Missing credentials' });
        const user = findUserByUsername(username);
        if (!user || !verifyPassword(user, password)) {
          return sendJSON(res, 401, { error: 'Invalid credentials' });
        }
        const sid = createSession(user.id);
        setSessionCookie(res, sid);
        return sendJSON(res, 200, { ok: true, user: { id: user.id, username: user.username } });
      });
    }
    if (pathname === '/api/logout' && req.method === 'POST') {
      if (session) destroySession(session.id);
      // Clear cookie
      res.writeHead(200, { 'Set-Cookie': 'sessionId=; Max-Age=0; Path=/' });
      res.end(JSON.stringify({ ok: true }));
      return;
    }
    if (pathname === '/api/events' && req.method === 'GET') {
      // Return list of events (basic info)
      const eventsSummary = data.events.map(e => ({ id: e.id, title: e.title, startISO: e.startISO, endISO: e.endISO, slotMinutes: e.slotMinutes, ownerId: e.ownerId }));
      return sendJSON(res, 200, { events: eventsSummary });
    }
    if (pathname === '/api/events' && req.method === 'POST') {
      // Create new event (requires login)
      if (!session) return sendJSON(res, 401, { error: 'Not authenticated' });
      return parseBody(req, (err, body) => {
        if (err) return sendJSON(res, 400, { error: 'Invalid body' });
        const { title, startISO, endISO, slotMinutes } = body;
        if (!title || !startISO || !endISO || !slotMinutes) {
          return sendJSON(res, 400, { error: 'Missing fields' });
        }
        const event = createEvent(title, startISO, endISO, Number(slotMinutes), session.userId);
        return sendJSON(res, 200, { ok: true, event });
      });
    }
    // Event detail: GET /api/event/:id
    const eventDetailMatch = pathname.match(/^\/api\/event\/(\d+)$/);
    if (eventDetailMatch && req.method === 'GET') {
      const eventId = Number(eventDetailMatch[1]);
      const event = findEventById(eventId);
      if (!event) return sendJSON(res, 404, { error: 'Event not found' });
      const { aggregated, maxCount } = buildAggregatedAvailability(event.id);
      // We also include current user's availability if logged in
      let userSlots = [];
      if (session) {
        const rec = getAvailabilityRecord(event.id, session.userId);
        if (rec) userSlots = rec.slots;
      }
      return sendJSON(res, 200, { event, aggregated, maxCount, userSlots });
    }
    // Submit availability: POST /api/event/:id/availability
    const availMatch = pathname.match(/^\/api\/event\/(\d+)\/availability$/);
    if (availMatch && req.method === 'POST') {
      if (!session) return sendJSON(res, 401, { error: 'Not authenticated' });
      const eventId = Number(availMatch[1]);
      const event = findEventById(eventId);
      if (!event) return sendJSON(res, 404, { error: 'Event not found' });
      return parseBody(req, (err, body) => {
        if (err) return sendJSON(res, 400, { error: 'Invalid body' });
        let { slots } = body;
        if (!Array.isArray(slots)) {
          // Allow comma‑separated string
          if (typeof slots === 'string') {
            slots = slots.split(',').filter(s => s !== '').map(s => Number(s));
          } else {
            slots = [];
          }
        }
        slots = slots.map(n => Number(n)).filter(n => !isNaN(n));
        const rec = getAvailabilityRecord(event.id, session.userId, true);
        rec.slots = [...new Set(slots)];
        saveData();
        return sendJSON(res, 200, { ok: true });
      });
    }
    // Delete event: DELETE /api/event/:id
    const deleteMatch = pathname.match(/^\/api\/event\/(\d+)$/);
    if (deleteMatch && req.method === 'DELETE') {
      if (!session) return sendJSON(res, 401, { error: 'Not authenticated' });
      const eventId = Number(deleteMatch[1]);
      const event = findEventById(eventId);
      if (!event) return sendJSON(res, 404, { error: 'Event not found' });
      // Only owner can delete
      if (event.ownerId !== session.userId) return sendJSON(res, 403, { error: 'Forbidden' });
      // Remove event
      data.events = data.events.filter(e => e.id !== eventId);
      // Remove associated availability
      data.availability = data.availability.filter(a => a.eventId !== eventId);
      saveData();
      return sendJSON(res, 200, { ok: true });
    }
    // Who selected slot: GET /api/event/:id/who?slot=N
    const whoMatch = pathname.match(/^\/api\/event\/(\d+)\/who$/);
    if (whoMatch && req.method === 'GET') {
      const eventId = Number(whoMatch[1]);
      const event = findEventById(eventId);
      if (!event) return sendJSON(res, 404, { error: 'Event not found' });
      const slotStr = parsedUrl.query.slot;
      const slotIndex = Number(slotStr);
      if (isNaN(slotIndex)) return sendJSON(res, 400, { error: 'Invalid slot index' });
      const { aggregated } = buildAggregatedAvailability(eventId);
      const info = aggregated[slotIndex] || { count: 0, names: [] };
      return sendJSON(res, 200, info);
    }
    return sendJSON(res, 404, { error: 'Not found' });
  }

  // All other requests: 404 Not Found
  res.writeHead(404, { 'Content-Type': 'text/plain' });
  res.end('Not Found');
}

// Helper to send JSON response
function sendJSON(res, status, obj) {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(obj));
}

// Helper to set session cookie
function setSessionCookie(res, sid) {
  const cookie = `sessionId=${sid}; HttpOnly; Path=/; Max-Age=${SESSION_TTL_MS / 1000}`;
  res.setHeader('Set-Cookie', cookie);
}

// Load data at startup
loadData();

// Create HTTP server
const server = http.createServer(handleRequest);

// Start listening
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`When2Meet clone server is running on http://localhost:${PORT}`);
});