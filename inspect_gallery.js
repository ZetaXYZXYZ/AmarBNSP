const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const db = new sqlite3.Database(path.join(__dirname, 'data.db'));
db.all('SELECT id,title,filename,created_at FROM gallery_images', [], (err, rows) => {
  if (err) {
    console.error(err);
    process.exit(1);
  }
  console.log('count=', rows.length);
  console.log(JSON.stringify(rows, null, 2));
  process.exit(0);
});
