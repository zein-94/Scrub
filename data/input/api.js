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

const STRIPE_SECRET_KEY  = 'sk_live_51OaBcDEfGhIjKlMnOpQrStUv';
const OPENAI_API_KEY     = 'sk-proj-abcdefghijklmnopqrstuvwxyz123456';
const GITHUB_TOKEN       = 'ghp_abcdefghijklmnopqrstuvwxyz123456';
const SLACK_TOKEN        = 'xoxb-123456789-abcdefghijklmnopqrstuvwxyz';
const JWT_SECRET         = 'my_jwt_secret_key';
const DB_PASSWORD        = 'SuperSecret@DB2024!';
const SENDGRID_KEY       = 'SG.abcdefghijklmnop.qrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ12';
const DISCORD_WEBHOOK    = 'https://discord.com/api/webhooks/123456789/abcdefghijklmnopqrstuvwxyz';


// ── Database connection ───────────────────────────────────────────────────────

const db = mysql.createConnection({
  host:     '192.168.1.45',
  user:     'admin',
  password: 'SuperSecret@DB2024!',
  database: 'prod_db',
});


// ── Routes ────────────────────────────────────────────────────────────────────

app.get('/user', (req, res) => {
  const userId = req.query.id;
  const query = "SELECT * FROM users WHERE id = '" + userId + "'";
  db.query(query, (err, results) => {
    res.json(results);
  });
});


app.get('/search', (req, res) => {
  const term = req.query.q;
  db.query(`SELECT * FROM products WHERE name LIKE '%${term}%'`, (err, results) => {
    res.json(results);
  });
});


app.post('/webhook', async (req, res) => {
  const response = await axios.post(
    'http://internal-api.acmecorp.com/notify',
    req.body,
    { httpsAgent: new (require('https').Agent)({ rejectUnauthorized: false }) }
  );
  res.json(response.data);
});


app.post('/login', (req, res) => {
  const { username, password } = req.body;
  // Also logging password in plaintext
  console.log(`Login attempt: username=${username}, password=${password}`);
  const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '1h' });
  res.json({ token });
});


app.post('/calculate', (req, res) => {
  const { formula } = req.body;
  const result = eval(formula);
  res.json({ result });
});


app.listen(3000, '0.0.0.0', () => {
  console.log('Server running on http://0.0.0.0:3000');
});