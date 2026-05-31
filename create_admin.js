const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const path = require('path');

const DB_FILE = path.join(__dirname, 'data.db');
const db = new sqlite3.Database(DB_FILE);

const email = process.env.ADMIN_EMAIL || 'admin@example.com';
const password = process.env.ADMIN_PASSWORD || 'admin123';
const name = process.env.ADMIN_NAME || 'Administrator';

(async () => {
  try {
    const hash = await bcrypt.hash(password, 10);
    db.run('INSERT INTO users (name,email,password_hash,is_admin) VALUES (?,?,?,1)', [name, email, hash], function(err) {
      if (err) {
        if (err.message && err.message.includes('UNIQUE')) {
          console.error('Error: email already exists');
          process.exit(2);
        }
        console.error('DB error:', err.message || err);
        process.exit(1);
      }
      console.log('Admin created:', { id: this.lastID, email, name });
      console.log('Password (plaintext):', password);
      process.exit(0);
    });
  } catch (e) {
    console.error('Hash error', e);
    process.exit(1);
  }
})();
