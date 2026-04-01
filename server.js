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

// Proxy — uses http-proxy-middleware v3 on:{} event handler syntax
const ccProxy = createProxyMiddleware({
  target: 'https://api.checkoutchamp.com',
  changeOrigin: true,
  on: {
    proxyReq: (proxyReq) => {
      // Strip relay secret — CC must never see it
      proxyReq.removeHeader('x-relay-secret');

      // CRITICAL: Strip all forwarding headers injected by Traefik.
      // Without this, CC reads X-Forwarded-For and sees the original
      // client IP instead of this VPS IP (150.230.35.80).
      proxyReq.removeHeader('x-forwarded-for');
      proxyReq.removeHeader('x-forwarded-host');
      proxyReq.removeHeader('x-forwarded-proto');
      proxyReq.removeHeader('x-forwarded-server');
      proxyReq.removeHeader('x-real-ip');
      proxyReq.removeHeader('via');
    },
    proxyRes: (proxyRes, req) => {
      proxyRes.headers['access-control-allow-origin'] = req.headers.origin || '*';
    },
    error: (err, req, res) => {
      console.error('[relay] Proxy error:', err.message);
      res.status(502).json({ error: 'Bad Gateway', details: err.message });
    },
  },
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
