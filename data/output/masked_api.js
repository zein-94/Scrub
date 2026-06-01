/**
 * api.js
 * Backend API handler — Node.js / Express
 */

const express = require('express');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2');
const axios = require('axios');

const app = express();
app.use(express.json());


// ── Hardcoded credentials ─────────────────────────────────────────────────────

const STRIPE_SECRET_KEY  = '{{STRIPE_KEY_1}}';
const OPENAI_API_KEY     = '{{API_KEY_1}}';
const GITHUB_TOKEN       = '{{GITHUB_TOKEN_1}}';
const SLACK_TOKEN        = '{{SLACK_TOKEN_1}}';
const JWT_SECRET         = '{{SECRET_1}}';
const DB_PASSWORD        = '{{PASSWORD_1}}';
const SENDGRID_KEY       = '{{SENDGRID_KEY_1}}';
const DISCORD_WEBHOOK    = '{{WEBHOOK_URL_1}}';


// ── Database connection ───────────────────────────────────────────────────────

const db = mysql.createConnection({
  host:     '{{IP_ADDRESS_1}}',
  user:     'admin',
  password: '{{PASSWORD_1}}',
  database: 'prod_db',
});


// ── Routes ────────────────────────────────────────────────────────────────────

// VULNERABILITY: SQL injection via string concatenation
app.get('/user', (req, res) => {
  const userId = req.query.id;
  const query = "SELECT * FROM users WHERE id = '" + userId + "'";
  db.query(query, (err, results) => {
    res.json(results);
  });
});


// VULNERABILITY: SQL injection via template literal
app.get('/search', (req, res) => {
  const term = req.query.q;
  db.query(`SELECT * FROM products WHERE name LIKE '%${term}%'`, (err, results) => {
    res.json(results);
  });
});


// VULNERABILITY: TLS verification disabled
app.post('/webhook', async (req, res) => {
  const response = await axios.post(
    'http://internal-api.acmecorp.com/notify',
    req.body,
    { httpsAgent: new (require('https').Agent)({ rejectUnauthorized: false }) }
  );
  res.json(response.data);
});


// VULNERABILITY: JWT with hardcoded secret
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  // Also logging password in plaintext
  console.log(`Login attempt: username=${username}, password=${password}`);
  const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '1h' });
  res.json({ token });
});


// VULNERABILITY: eval on user input
app.post('/calculate', (req, res) => {
  const { formula } = req.body;
  const result = eval(formula);
  res.json({ result });
});


// Server — binding to all interfaces
app.listen(3000, '0.0.0.0', () => {
  console.log('Server running on http://0.0.0.0:3000');
});