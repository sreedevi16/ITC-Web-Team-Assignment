/**
 * ITC Finance Tracker - REST API
 * Task 3: Backend Skills Evaluation
 *
 * Stack: Node.js + Express + SQLite (better-sqlite3)
 * Auth:  JWT (optional bonus)
 *
 * Endpoints:
 *   POST   /api/auth/register
 *   POST   /api/auth/login
 *   GET    /api/transactions        → all transactions (auth required)
 *   POST   /api/transactions        → create transaction
 *   PUT    /api/transactions/:id    → update transaction
 *   DELETE /api/transactions/:id    → delete transaction
 *   GET    /api/summary             → totals & category breakdown
 */

const express = require('express');
const Database = require('better-sqlite3');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'itc-secret-key-change-in-production';

// ===== MIDDLEWARE =====
app.use(cors());
app.use(express.json());

// Request logger
app.use((req, _res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
  next();
});

// ===== DATABASE SETUP =====
const db = new Database('./finance.db');

// Enable WAL mode for better performance
db.pragma('journal_mode = WAL');

// Create tables
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    name      TEXT    NOT NULL,
    email     TEXT    NOT NULL UNIQUE,
    password  TEXT    NOT NULL,
    created_at TEXT   DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS transactions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL,
    type        TEXT    NOT NULL CHECK(type IN ('income','expense')),
    amount      REAL    NOT NULL CHECK(amount > 0),
    category    TEXT    NOT NULL,
    description TEXT    NOT NULL,
    date        TEXT    NOT NULL,
    created_at  TEXT    DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
`);

// ===== AUTH MIDDLEWARE =====
function authenticate(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized: no token provided' });
  }
  try {
    const token = header.split(' ')[1];
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Unauthorized: invalid or expired token' });
  }
}

// ===== VALIDATION HELPERS =====
const VALID_TYPES = ['income', 'expense'];
const VALID_CATEGORIES = [
  'Salary','Freelance','Investment','Gift','Other Income',
  'Food','Transport','Rent','Shopping','Health',
  'Education','Entertainment','Utilities','Other'
];

function validateTransaction({ type, amount, category, description, date }) {
  const errors = [];
  if (!VALID_TYPES.includes(type)) errors.push('type must be "income" or "expense"');
  if (!amount || isNaN(amount) || amount <= 0) errors.push('amount must be a positive number');
  if (!VALID_CATEGORIES.includes(category)) errors.push(`invalid category: ${category}`);
  if (!description || description.trim().length < 2) errors.push('description must be at least 2 characters');
  if (!date || !/^\d{4}-\d{2}-\d{2}$/.test(date)) errors.push('date must be in YYYY-MM-DD format');
  return errors;
}

// ===== AUTH ROUTES =====

// Register
app.post('/api/auth/register', (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) {
    return res.status(400).json({ error: 'name, email, and password are required' });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: 'password must be at least 6 characters' });
  }

  const hashed = bcrypt.hashSync(password, 10);
  try {
    const stmt = db.prepare('INSERT INTO users (name, email, password) VALUES (?, ?, ?)');
    const result = stmt.run(name, email.toLowerCase(), hashed);
    const token = jwt.sign({ id: result.lastInsertRowid, email, name }, JWT_SECRET, { expiresIn: '7d' });
    res.status(201).json({ message: 'Registered successfully', token, user: { id: result.lastInsertRowid, name, email } });
  } catch (err) {
    if (err.message.includes('UNIQUE')) {
      return res.status(409).json({ error: 'Email already registered' });
    }
    res.status(500).json({ error: 'Registration failed' });
  }
});

// Login
app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'email and password are required' });
  }

  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email.toLowerCase());
  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.status(401).json({ error: 'Invalid email or password' });
  }

  const token = jwt.sign({ id: user.id, email: user.email, name: user.name }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ message: 'Login successful', token, user: { id: user.id, name: user.name, email: user.email } });
});

// ===== TRANSACTION ROUTES (all require auth) =====

// GET /api/transactions — fetch all for current user
app.get('/api/transactions', authenticate, (req, res) => {
  const { type, category, from, to, limit = 100, offset = 0 } = req.query;

  let query = 'SELECT * FROM transactions WHERE user_id = ?';
  const params = [req.user.id];

  if (type) { query += ' AND type = ?'; params.push(type); }
  if (category) { query += ' AND category = ?'; params.push(category); }
  if (from) { query += ' AND date >= ?'; params.push(from); }
  if (to) { query += ' AND date <= ?'; params.push(to); }

  query += ' ORDER BY date DESC, created_at DESC LIMIT ? OFFSET ?';
  params.push(parseInt(limit), parseInt(offset));

  const transactions = db.prepare(query).all(...params);
  const total = db.prepare('SELECT COUNT(*) as c FROM transactions WHERE user_id = ?').get(req.user.id).c;

  res.json({ transactions, total, limit: parseInt(limit), offset: parseInt(offset) });
});

// POST /api/transactions — create a transaction
app.post('/api/transactions', authenticate, (req, res) => {
  const { type, amount, category, description, date } = req.body;
  const errors = validateTransaction({ type, amount, category, description, date });
  if (errors.length) return res.status(400).json({ error: 'Validation failed', details: errors });

  const stmt = db.prepare(
    'INSERT INTO transactions (user_id, type, amount, category, description, date) VALUES (?, ?, ?, ?, ?, ?)'
  );
  const result = stmt.run(req.user.id, type, parseFloat(amount), category, description.trim(), date);
  const tx = db.prepare('SELECT * FROM transactions WHERE id = ?').get(result.lastInsertRowid);

  res.status(201).json({ message: 'Transaction created', transaction: tx });
});

// PUT /api/transactions/:id — update a transaction
app.put('/api/transactions/:id', authenticate, (req, res) => {
  const existing = db.prepare('SELECT * FROM transactions WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
  if (!existing) return res.status(404).json({ error: 'Transaction not found' });

  const { type, amount, category, description, date } = req.body;
  // Merge with existing so partial updates work
  const merged = {
    type: type ?? existing.type,
    amount: amount ?? existing.amount,
    category: category ?? existing.category,
    description: description ?? existing.description,
    date: date ?? existing.date
  };

  const errors = validateTransaction(merged);
  if (errors.length) return res.status(400).json({ error: 'Validation failed', details: errors });

  db.prepare(
    'UPDATE transactions SET type=?, amount=?, category=?, description=?, date=? WHERE id=?'
  ).run(merged.type, parseFloat(merged.amount), merged.category, merged.description.trim(), merged.date, req.params.id);

  const updated = db.prepare('SELECT * FROM transactions WHERE id = ?').get(req.params.id);
  res.json({ message: 'Transaction updated', transaction: updated });
});

// DELETE /api/transactions/:id — delete a transaction
app.delete('/api/transactions/:id', authenticate, (req, res) => {
  const existing = db.prepare('SELECT * FROM transactions WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
  if (!existing) return res.status(404).json({ error: 'Transaction not found' });

  db.prepare('DELETE FROM transactions WHERE id = ?').run(req.params.id);
  res.json({ message: 'Transaction deleted', id: parseInt(req.params.id) });
});

// GET /api/summary — totals + category breakdown
app.get('/api/summary', authenticate, (req, res) => {
  const uid = req.user.id;
  const { from, to } = req.query;

  let dateFilter = '';
  const params = [uid];
  if (from) { dateFilter += ' AND date >= ?'; params.push(from); }
  if (to)   { dateFilter += ' AND date <= ?'; params.push(to); }

  const totals = db.prepare(`
    SELECT
      SUM(CASE WHEN type='income'  THEN amount ELSE 0 END) as total_income,
      SUM(CASE WHEN type='expense' THEN amount ELSE 0 END) as total_expense,
      COUNT(*) as transaction_count
    FROM transactions WHERE user_id = ?${dateFilter}
  `).get(...params);

  const byCategory = db.prepare(`
    SELECT category, type, SUM(amount) as total, COUNT(*) as count
    FROM transactions WHERE user_id = ?${dateFilter}
    GROUP BY category, type ORDER BY total DESC
  `).all(...params);

  const byMonth = db.prepare(`
    SELECT strftime('%Y-%m', date) as month,
      SUM(CASE WHEN type='income'  THEN amount ELSE 0 END) as income,
      SUM(CASE WHEN type='expense' THEN amount ELSE 0 END) as expense
    FROM transactions WHERE user_id = ?${dateFilter}
    GROUP BY month ORDER BY month DESC LIMIT 12
  `).all(...params);

  res.json({
    balance: (totals.total_income || 0) - (totals.total_expense || 0),
    total_income: totals.total_income || 0,
    total_expense: totals.total_expense || 0,
    transaction_count: totals.transaction_count,
    by_category: byCategory,
    by_month: byMonth
  });
});

// Health check
app.get('/api/health', (_req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// 404 handler
app.use((_req, res) => res.status(404).json({ error: 'Route not found' }));

// Global error handler
app.use((err, _req, res, _next) => {
  console.error(err);
  res.status(500).json({ error: 'Internal server error' });
});

// Start server
app.listen(PORT, () => {
  console.log(`✅ ITC Finance API running on http://localhost:${PORT}`);
  console.log(`   Health: http://localhost:${PORT}/api/health`);
});

module.exports = app;
