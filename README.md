# Auth (Sign up / Sign in) untuk situs

File yang ditambahkan:

- `signup.html` — halaman frontend untuk mendaftar
- `signin.html` — halaman frontend untuk login
- `server.js` — backend minimal (Express + SQLite)
- `package.json` — script start

Cara menjalankan (di folder project):

```bash
npm init -y    # jika belum ada
npm install express sqlite3 bcryptjs jsonwebtoken
node server.js
```

Buka `http://localhost:3000/signup.html` atau `signin.html` untuk mencoba.

Halaman publik:
- `Index.html`, `about.html`, `products.html` — halaman yang dapat diakses sebelum login
- `signin.html`, `signup.html` — halaman auth publik untuk login / daftar

Halaman privat setelah login:
- `gallery.html`, `clients.html`, `articles.html`, `events.html`, `contact.html` — hanya dapat diakses setelah login
- `admin.html` — hanya dapat diakses oleh akun admin setelah login

Catatan keamanan:
- Atur `JWT_SECRET` di environment pada production.
- Gunakan HTTPS dan cookie HttpOnly jika perlu.
