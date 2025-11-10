require('dotenv').config();
const express = require('express');
const fetch = require('node-fetch');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
app.use(express.json({ limit: '1mb' }));
app.use(cookieParser());

const PORT = process.env.PORT || 3000;
const N8N_WEBHOOK_URL = process.env.N8N_WEBHOOK_URL;
const N8N_USERNAME = process.env.N8N_USERNAME;
const N8N_PASSWORD = process.env.N8N_PASSWORD;
const JWT_SECRET = process.env.JWT_SECRET || 'change_this_in_prod';

if (!N8N_WEBHOOK_URL || !N8N_USERNAME || !N8N_PASSWORD) {
  console.warn('Warning: N8N_WEBHOOK_URL, N8N_USERNAME or N8N_PASSWORD not set in environment. Set them before production deployment.');
}

// Serve static files (your index.html lives at project root)
app.use(express.static(path.join(__dirname)));

// POST /login - validate credentials against env and set httpOnly cookie
app.post('/login', (req, res) => {
  const { username, password } = req.body || {};
  if (username === N8N_USERNAME && password === N8N_PASSWORD) {
    const token = jwt.sign({ sub: username }, JWT_SECRET, { expiresIn: '2h' });
    res.cookie('session', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 2 * 60 * 60 * 1000,
    });
    return res.json({ ok: true });
  }
  return res.status(401).json({ ok: false, error: 'Invalid credentials' });
});

// POST /logout - clear cookie
app.post('/logout', (req, res) => {
  res.clearCookie('session');
  res.json({ ok: true });
});

// Proxy endpoint - forwards request to real n8n webhook attaching Basic Auth
app.all('/proxy/webhook', async (req, res) => {
  try {
    const token = req.cookies.session;
    if (!token) return res.status(401).json({ error: 'Not authenticated' });
    jwt.verify(token, JWT_SECRET);

    const basic = Buffer.from(`${N8N_USERNAME}:${N8N_PASSWORD}`).toString('base64');

    // Build headers for upstream request
    const upstreamHeaders = {
      'Content-Type': req.get('content-type') || 'application/json',
      Authorization: `Basic ${basic}`,
    };

    // Forward body when applicable
    const body = ['GET', 'HEAD'].includes(req.method) ? undefined : JSON.stringify(req.body || {});

    const upstream = await fetch(N8N_WEBHOOK_URL, {
      method: req.method,
      headers: upstreamHeaders,
      body,
    });

    const text = await upstream.text();
    res.status(upstream.status);
    upstream.headers.forEach((v, k) => {
      if (!['transfer-encoding', 'content-encoding', 'connection'].includes(k.toLowerCase())) {
        res.setHeader(k, v);
      }
    });
    res.send(text);
  } catch (err) {
    console.error('Proxy error', err);
    res.status(500).json({ error: 'Proxy error' });
  }
});

app.listen(PORT, () => {
  console.log(`Server listening on http://localhost:${PORT}`);
});
