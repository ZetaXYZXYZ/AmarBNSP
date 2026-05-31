const express = require('express');
const path = require('path');
const fs = require('fs');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');

const DB_FILE = path.join(__dirname, 'data.db');
const UPLOAD_DIR = path.join(__dirname, 'uploads');
fs.mkdirSync(UPLOAD_DIR, { recursive: true });
const db = new Database(DB_FILE);

// Enable foreign keys
db.pragma('journal_mode = WAL');

// Create tables
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    is_admin INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS uploads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    link TEXT,
    filename TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS gallery_images (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    filename TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS clients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    link TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS articles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    link TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS cart_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    product_id INTEGER NOT NULL,
    quantity INTEGER NOT NULL DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, product_id)
  );

  CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS order_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    order_id INTEGER NOT NULL,
    product_id INTEGER NOT NULL,
    quantity INTEGER NOT NULL DEFAULT 1
  );
`);

// Initialize default clients if empty
const clientCount = db.prepare('SELECT COUNT(*) AS count FROM clients').get();
if (clientCount.count === 0) {
  const stmt = db.prepare('INSERT INTO clients (name) VALUES (?)');
  ['Klien A', 'Klien B', 'Klien C', 'Klien D', 'Klien E', 'Klien F'].forEach(name => stmt.run(name));
}

const upload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => cb(null, UPLOAD_DIR),
    filename: (req, file, cb) => {
      const safeName = `${Date.now()}-${file.originalname.replace(/[^a-zA-Z0-9.\-_]/g, '_')}`;
      cb(null, safeName);
    }
  }),
  limits: { fileSize: 10 * 1024 * 1024 }
});

const app = express();
app.use(express.json());
app.use('/uploads', express.static(UPLOAD_DIR));

const PUBLIC_HTML_PATHS = new Set([
  '/',
  '/index.html',
  '/Index.html',
  '/about.html',
  '/products.html',
  '/signin.html',
  '/signup.html'
]);

function getHtmlRequestPath(req) {
  return req.path === '/' ? '/Index.html' : req.path;
}

function requireLoginForPage(req, res, next) {
  const token = getTokenFromRequest(req);
  if (!token) return res.redirect('/signin.html');
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (e) {
    return res.redirect('/signin.html');
  }
}

function requireAdminForPage(req, res, next) {
  requireLoginForPage(req, res, () => {
    const userId = req.user && req.user.id;
    if (!userId) return res.redirect('/signin.html');
    const row = db.prepare('SELECT is_admin FROM users WHERE id = ?').get(userId);
    if (!row || !row.is_admin) {
      return res.status(403).send('Akses admin ditolak');
    }
    next();
  });
}

app.use((req, res, next) => {
  if (req.method !== 'GET') return next();
  const pathname = getHtmlRequestPath(req);
  const normalized = pathname.toLowerCase();
  if (!normalized.endsWith('.html') && normalized !== '/index.html') return next();
  if (PUBLIC_HTML_PATHS.has(normalized) || PUBLIC_HTML_PATHS.has(pathname)) {
    return next();
  }
  if (normalized === '/admin.html') {
    return requireAdminForPage(req, res, next);
  }
  return requireLoginForPage(req, res, next);
});

app.get('/admin.html', authenticateToken, requireAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, 'admin.html'));
});

app.use(express.static(path.join(__dirname)));

const JWT_SECRET = process.env.JWT_SECRET || 'change_this_in_production';

function getTokenFromRequest(req) {
  const auth = req.headers.authorization || '';
  const m = auth.match(/^Bearer\s+(.+)$/i);
  if (m) return m[1];
  const cookieHeader = req.headers.cookie || '';
  const parts = cookieHeader.split(';').map(s => s.trim());
  for (const p of parts) {
    if (p.startsWith('token=')) return p.substring('token='.length);
  }
  return null;
}

function setTokenCookie(res, token, req) {
  const isSecure = req.secure || req.headers['x-forwarded-proto'] === 'https' || process.env.NODE_ENV === 'production';
  res.cookie('token', token, {
    httpOnly: true,
    secure: isSecure,
    sameSite: 'lax',
    maxAge: 2 * 60 * 60 * 1000 // 2 hours
  });
}

function authenticateToken(req, res, next) {
  const token = getTokenFromRequest(req);
  if (!token) return res.status(401).send('Unauthorized');
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (e) {
    res.status(401).send('Invalid token');
  }
}

function requireAdmin(req, res, next) {
  const userId = req.user && req.user.id;
  if (!userId) return res.status(401).send('Unauthorized');
  const row = db.prepare('SELECT is_admin FROM users WHERE id = ?').get(userId);
  if (!row || !row.is_admin) return res.status(403).send('Forbidden');
  next();
}

app.post('/api/signup', async (req, res) => {
  const { name, email, password, adminCode } = req.body || {};
  if (!email || !password) return res.status(400).send('Email dan password wajib');
  try {
    const hash = await bcrypt.hash(password, 10);
    const isAdmin = (adminCode && process.env.ADMIN_CODE && adminCode === process.env.ADMIN_CODE) ? 1 : 0;
    const result = db.prepare('INSERT INTO users (name,email,password_hash,is_admin) VALUES (?,?,?,?)').run(name || null, email, hash, isAdmin);
    if (!result) return res.status(400).send('Email sudah terdaftar');
    const token = jwt.sign({ id: result.lastInsertRowid, email }, JWT_SECRET, { expiresIn: '2h' });
    setTokenCookie(res, token, req);
    res.status(201).json({ id: result.lastInsertRowid });
  } catch (e) {
    if (e.message.includes('UNIQUE')) return res.status(400).send('Email sudah terdaftar');
    res.status(500).send('Server error');
  }
});

app.post('/api/signin', (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).send('Email dan password wajib');
  try {
    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
    if (!user) return res.status(400).send('Email atau password salah');
    bcrypt.compare(password, user.password_hash, (err, ok) => {
      if (err || !ok) return res.status(400).send('Email atau password salah');
      const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '2h' });
      setTokenCookie(res, token, req);
      res.json({ ok: true });
    });
  } catch (e) {
    res.status(500).send('Server error');
  }
});

app.get('/api/me', (req, res) => {
  const token = getTokenFromRequest(req);
  if (!token) return res.status(401).send('Unauthorized');
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const user = db.prepare('SELECT id,name,email,created_at,is_admin FROM users WHERE id = ?').get(payload.id);
    if (!user) return res.status(404).send('User not found');
    res.json(user);
  } catch (e) {
    res.status(401).send('Invalid token');
  }
});

app.get('/api/admin/uploads', authenticateToken, (req, res) => {
  try {
    const rows = db.prepare('SELECT id, title, link, filename, created_at FROM uploads ORDER BY created_at DESC').all();
    res.json(rows);
  } catch (e) {
    res.status(500).send('Server error');
  }
});

app.get('/api/gallery', (req, res) => {
  try {
    const rows = db.prepare('SELECT id, title, filename, created_at FROM gallery_images ORDER BY created_at DESC').all();
    res.json(rows);
  } catch (e) {
    res.status(500).send('Server error');
  }
});

app.post('/api/admin/uploads', authenticateToken, upload.single('file'), (req, res) => {
  const { title, link } = req.body || {};
  if (!title) return res.status(400).send('Judul wajib diisi');
  try {
    const filename = req.file ? req.file.filename : null;
    const result = db.prepare('INSERT INTO uploads (title, link, filename) VALUES (?,?,?)').run(title, link || null, filename);
    res.status(201).json({ id: result.lastInsertRowid, title, link, filename });
  } catch (e) {
    res.status(500).send('Server error');
  }
});

app.post('/api/admin/gallery', authenticateToken, upload.fields([{ name: 'files', maxCount: 10 }, { name: 'file', maxCount: 10 }]), (req, res) => {
  const { title } = req.body || {};
  if (!title) return res.status(400).send('Judul wajib diisi');
  try {
    let files = [];
    if (req.files) {
      Object.keys(req.files).forEach(k => {
        if (Array.isArray(req.files[k])) files.push(...req.files[k]);
      });
    }
    if (req.file) files.push(req.file);
    if (!files.length) return res.status(400).send('File foto wajib diunggah');
    
    const stmt = db.prepare('INSERT INTO gallery_images (title, filename) VALUES (?,?)');
    const insert = db.transaction((filesList) => {
      filesList.forEach(file => stmt.run(title, file.filename));
    });
    insert(files);
    
    res.status(201).json({ uploaded: files.length, files: files.map(f => ({ title, filename: f.filename })) });
  } catch (e) {
    res.status(500).send('Server error');
  }
});

app.delete('/api/admin/gallery/:id', authenticateToken, (req, res) => {
  const id = Number(req.params.id);
  try {
    const row = db.prepare('SELECT filename FROM gallery_images WHERE id = ?').get(id);
    if (!row) return res.status(404).send('Image not found');
    
    const filePath = path.join(UPLOAD_DIR, row.filename);
    fs.unlink(filePath, (e) => {
      // ignore unlink errors
    });
    
    db.prepare('DELETE FROM gallery_images WHERE id = ?').run(id);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).send('Server error');
  }
});

app.get('/api/clients', authenticateToken, (req, res) => {
  try {
    const rows = db.prepare('SELECT id, name FROM clients ORDER BY id ASC').all();
    res.json(rows);
  } catch (e) {
    res.status(500).send('Server error');
  }
});

app.get('/api/products', (req, res) => {
  try {
    const rows = db.prepare('SELECT id, title, description, link, created_at FROM products ORDER BY created_at DESC').all();
    res.json(rows);
  } catch (e) {
    res.status(500).send('Server error');
  }
});

app.get('/api/articles', authenticateToken, (req, res) => {
  try {
    const rows = db.prepare('SELECT id, title, description, link, created_at FROM articles ORDER BY created_at DESC').all();
    res.json(rows);
  } catch (e) {
    res.status(500).send('Server error');
  }
});

app.post('/api/admin/products', authenticateToken, requireAdmin, (req, res) => {
  const { title, description, link } = req.body || {};
  if (!title || !description) return res.status(400).send('Judul dan deskripsi produk wajib diisi');
  try {
    const result = db.prepare('INSERT INTO products (title, description, link) VALUES (?,?,?)').run(title, description, link || null);
    res.status(201).json({ id: result.lastInsertRowid, title, description, link });
  } catch (e) {
    res.status(500).send('Server error');
  }
});

app.patch('/api/admin/products/:id', authenticateToken, requireAdmin, (req, res) => {
  const { title, description, link } = req.body || {};
  const id = Number(req.params.id);
  if (!title || !description) return res.status(400).send('Judul dan deskripsi produk wajib diisi');
  try {
    const result = db.prepare('UPDATE products SET title = ?, description = ?, link = ? WHERE id = ?').run(title, description, link || null, id);
    if (result.changes === 0) return res.status(404).send('Produk tidak ditemukan');
    res.json({ ok: true });
  } catch (e) {
    res.status(500).send('Server error');
  }
});

app.delete('/api/admin/products/:id', authenticateToken, requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  try {
    const result = db.prepare('DELETE FROM products WHERE id = ?').run(id);
    if (result.changes === 0) return res.status(404).send('Produk tidak ditemukan');
    res.json({ ok: true });
  } catch (e) {
    res.status(500).send('Server error');
  }
});

app.post('/api/admin/articles', authenticateToken, requireAdmin, (req, res) => {
  const { title, description, link } = req.body || {};
  if (!title || !description) return res.status(400).send('Judul dan deskripsi artikel wajib diisi');
  try {
    const result = db.prepare('INSERT INTO articles (title, description, link) VALUES (?,?,?)').run(title, description, link || null);
    res.status(201).json({ id: result.lastInsertRowid, title, description, link });
  } catch (e) {
    res.status(500).send('Server error');
  }
});

app.get('/api/cart', authenticateToken, (req, res) => {
  const userId = req.user && req.user.id;
  try {
    const rows = db.prepare(`
      SELECT c.product_id, c.quantity, p.title, p.description, p.link
      FROM cart_items c JOIN products p ON p.id = c.product_id
      WHERE c.user_id = ?
    `).all(userId);
    res.json(rows);
  } catch (e) {
    res.status(500).send('Server error');
  }
});

app.post('/api/cart', authenticateToken, (req, res) => {
  const userId = req.user && req.user.id;
  const { product_id, quantity } = req.body || {};
  const qty = Number(quantity) || 1;
  if (!product_id) return res.status(400).send('product_id wajib');
  try {
    const prod = db.prepare('SELECT id FROM products WHERE id = ?').get(product_id);
    if (!prod) return res.status(400).send('Produk tidak ditemukan');
    
    const row = db.prepare('SELECT id, quantity FROM cart_items WHERE user_id = ? AND product_id = ?').get(userId, product_id);
    if (row) {
      const newQty = row.quantity + qty;
      db.prepare('UPDATE cart_items SET quantity = ? WHERE id = ?').run(newQty, row.id);
      res.json({ ok: true });
    } else {
      const result = db.prepare('INSERT INTO cart_items (user_id, product_id, quantity) VALUES (?,?,?)').run(userId, product_id, qty);
      res.status(201).json({ id: result.lastInsertRowid });
    }
  } catch (e) {
    res.status(500).send('Server error');
  }
});

app.patch('/api/cart/:productId', authenticateToken, (req, res) => {
  const userId = req.user && req.user.id;
  const productId = Number(req.params.productId);
  const { quantity } = req.body || {};
  const qty = Number(quantity);
  if (isNaN(qty) || qty < 0) return res.status(400).send('quantity invalid');
  try {
    if (qty === 0) {
      db.prepare('DELETE FROM cart_items WHERE user_id = ? AND product_id = ?').run(userId, productId);
      return res.json({ ok: true });
    }
    const result = db.prepare('UPDATE cart_items SET quantity = ? WHERE user_id = ? AND product_id = ?').run(qty, userId, productId);
    if (result.changes === 0) return res.status(404).send('Item tidak ditemukan');
    res.json({ ok: true });
  } catch (e) {
    res.status(500).send('Server error');
  }
});

app.delete('/api/cart/:productId', authenticateToken, (req, res) => {
  const userId = req.user && req.user.id;
  const productId = Number(req.params.productId);
  try {
    db.prepare('DELETE FROM cart_items WHERE user_id = ? AND product_id = ?').run(userId, productId);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).send('Server error');
  }
});

app.post('/api/cart/checkout', authenticateToken, (req, res) => {
  const userId = req.user && req.user.id;
  try {
    const items = db.prepare('SELECT product_id, quantity FROM cart_items WHERE user_id = ?').all(userId);
    if (!items || !items.length) return res.status(400).send('Keranjang kosong');
    
    const insertOrder = db.transaction(() => {
      const orderResult = db.prepare('INSERT INTO orders (user_id) VALUES (?)').run(userId);
      const orderId = orderResult.lastInsertRowid;
      const stmt = db.prepare('INSERT INTO order_items (order_id, product_id, quantity) VALUES (?,?,?)');
      items.forEach(it => stmt.run(orderId, it.product_id, it.quantity));
      db.prepare('DELETE FROM cart_items WHERE user_id = ?').run(userId);
      return orderId;
    });
    
    const orderId = insertOrder();
    res.json({ ok: true, order_id: orderId });
  } catch (e) {
    res.status(500).send('Server error');
  }
});

app.get('/api/orders', authenticateToken, (req, res) => {
  const userId = req.user && req.user.id;
  try {
    const orders = db.prepare('SELECT id, created_at FROM orders WHERE user_id = ? ORDER BY created_at DESC').all(userId);
    const results = orders.map(order => {
      const items = db.prepare(`
        SELECT oi.product_id, oi.quantity, p.title, p.description, p.link 
        FROM order_items oi 
        JOIN products p ON p.id = oi.product_id 
        WHERE oi.order_id = ?
      `).all(order.id);
      return { id: order.id, created_at: order.created_at, items };
    });
    res.json(results);
  } catch (e) {
    res.status(500).send('Server error');
  }
});

app.patch('/api/admin/articles/:id', authenticateToken, requireAdmin, (req, res) => {
  const { title, description, link } = req.body || {};
  const id = Number(req.params.id);
  if (!title || !description) return res.status(400).send('Judul dan deskripsi artikel wajib diisi');
  try {
    const result = db.prepare('UPDATE articles SET title = ?, description = ?, link = ? WHERE id = ?').run(title, description, link || null, id);
    if (result.changes === 0) return res.status(404).send('Artikel tidak ditemukan');
    res.json({ ok: true });
  } catch (e) {
    res.status(500).send('Server error');
  }
});

app.delete('/api/admin/articles/:id', authenticateToken, requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  try {
    const result = db.prepare('DELETE FROM articles WHERE id = ?').run(id);
    if (result.changes === 0) return res.status(404).send('Artikel tidak ditemukan');
    res.json({ ok: true });
  } catch (e) {
    res.status(500).send('Server error');
  }
});

app.post('/api/admin/clients', authenticateToken, (req, res) => {
  const { name } = req.body || {};
  if (!name) return res.status(400).send('Nama klien wajib diisi');
  try {
    const result = db.prepare('INSERT INTO clients (name) VALUES (?)').run(name);
    res.status(201).json({ id: result.lastInsertRowid, name });
  } catch (e) {
    res.status(500).send('Server error');
  }
});

app.patch('/api/admin/clients/:id', authenticateToken, (req, res) => {
  const { name } = req.body || {};
  const id = Number(req.params.id);
  if (!name) return res.status(400).send('Nama klien wajib diisi');
  try {
    const result = db.prepare('UPDATE clients SET name = ? WHERE id = ?').run(name, id);
    if (result.changes === 0) return res.status(404).send('Klien tidak ditemukan');
    res.json({ ok: true });
  } catch (e) {
    res.status(500).send('Server error');
  }
});

app.delete('/api/admin/clients/:id', authenticateToken, (req, res) => {
  const id = Number(req.params.id);
  try {
    const result = db.prepare('DELETE FROM clients WHERE id = ?').run(id);
    if (result.changes === 0) return res.status(404).send('Klien tidak ditemukan');
    res.json({ ok: true });
  } catch (e) {
    res.status(500).send('Server error');
  }
});

app.post('/api/logout', (req, res) => {
  const isSecure = req.secure || req.headers['x-forwarded-proto'] === 'https' || process.env.NODE_ENV === 'production';
  res.clearCookie('token', { httpOnly: true, secure: isSecure, sameSite: 'lax' });
  res.json({ ok: true });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));
