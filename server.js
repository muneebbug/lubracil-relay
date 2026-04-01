const express = require('express');
const cors = require('cors');
const { createProxyMiddleware } = require('http-proxy-middleware');
const morgan = require('morgan');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 4000;
const RELAY_SECRET = process.env.RELAY_SECRET;
const ALLOWED_ORIGINS = process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : ['http://localhost:3000'];

// Middleware
app.use(cors({
  origin: function (origin, callback) {
    if (!origin || ALLOWED_ORIGINS.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  }
}));
app.use(morgan('dev'));

// Security Middleware: Relay Secret Guard
const checkSecret = (req, res, next) => {
  if (!RELAY_SECRET) return next(); // no secret configured — allow all (dev convenience)
  const provided = req.headers['x-relay-secret'];
  if (provided !== RELAY_SECRET) {
    return res.status(401).json({ error: 'Unauthorized: invalid or missing X-Relay-Secret header' });
  }
  next();
};

// Proxy middleware options
const ccProxy = createProxyMiddleware({
  target: 'https://api.checkoutchamp.com',
  changeOrigin: true,
  pathRewrite: {},
  onProxyReq: (proxyReq) => {
    // Strip the relay secret before forwarding — CC must never see it
    proxyReq.removeHeader('x-relay-secret');
  },
  onProxyRes: (proxyRes, req, res) => {
    proxyRes.headers['Access-Control-Allow-Origin'] = req.headers.origin || '*';
  },
  onError: (err, req, res) => {
    console.error('Proxy Error:', err);
    res.status(500).json({ error: 'Proxy implementation error', details: err.message });
  }
});

// Use proxy for all routes with secret guard
app.use('/', checkSecret, ccProxy);

// Start Server
app.listen(PORT, () => {
  console.log(`[relay] Running on http://0.0.0.0:${PORT}`);
  console.log(`[relay] Forwarding  -> https://api.checkoutchamp.com`);
  console.log(`[relay] Secret guard: ${RELAY_SECRET ? 'ENABLED' : 'DISABLED'}`);
  console.log(`[relay] Allowed origins: ${ALLOWED_ORIGINS.join(', ')}`);
});
