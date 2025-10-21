// index.js - Intranet RH demo (avec journalisation)
const express = require('express');
const fs = require('fs');
const path = require('path');
const session = require('express-session');
const bcrypt = require('bcrypt');
const helmet = require('helmet');

const app = express();
app.use(helmet());
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static('public'));

// ---------- Session config ----------
const isProd = process.env.NODE_ENV === 'production';
app.set('trust proxy', 1);
app.use(session({
  name: 'sid',
  secret: process.env.SESSION_SECRET || 'change_this_for_demo',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: isProd,
    sameSite: 'lax',
    maxAge: 1000 * 60 * 30
  }
}));

// ---------- Users (demo) ----------
const users = [];
(async () => {
  users.push({ id: 1, username: 'admin', passwordHash: await bcrypt.hash('adminpass', 10), admin: true });
  users.push({ id: 2, username: 'user',  passwordHash: await bcrypt.hash('userpass', 10),  admin: false });
})();

function escapeHtml(str) {
  return String(str).replace(/[&<>"'`=\/]/g, s => ({
    '&':'&amp;', '<':'&lt;','>':'&gt;','"':'&quot;', "'":'&#39;','/':'&#x2F;','`':'&#x60;','=':'&#x3D;'
  })[s]);
}

async function findUserByUsername(username) {
  return users.find(u => u.username === username) || null;
}

function requireLogin(req, res, next) {
  if (!req.session || !req.session.userId) {
    return res.status(401).send(`<h1>401 - Auth required</h1><p>Vous devez être connecté. <a href="/login">Se connecter</a></p>`);
  }
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session || !req.session.userId) return res.status(401).send('Authentification requise');
  const user = users.find(u => u.id === req.session.userId);
  if (!user || !user.admin) return res.status(403).send('<h1>403 Forbidden</h1><p>Accès réservé aux administrateurs.</p>');
  next();
}

// ---------- Journalisation des accès ----------
function logAccess(req, endpoint) {
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
  const timestamp = new Date().toISOString();
  const user = req.session.userId ? users.find(u => u.id === req.session.userId)?.username : 'guest';
  const logLine = `[${timestamp}] ${ip} - ${user} accessed ${endpoint}`;
  console.log(logLine);
  // Optionnel : enregistrer dans un fichier
  // fs.appendFileSync(path.join(__dirname, 'access.log'), logLine + '\n');
}

// ---------- Homepage ----------
app.get('/', (req, res) => {
  const loggedUser = req.session.userId ? users.find(u => u.id === req.session.userId) : null;
  res.send(`
    <h1>Intranet RH - Demo</h1>
    <p>Bienvenue sur l'intranet de démonstration. Utilisez le formulaire pour rechercher un employé.</p>
    <form method="POST" action="/search">
      <input name="q" placeholder="Nom ou partie du nom" />
      <button>Search</button>
    </form>
    <p>${loggedUser ? `Connecté: <b>${escapeHtml(loggedUser.username)}</b> (${loggedUser.admin ? 'admin' : 'utilisateur'}) — <a href="/logout">Logout</a>` : `<a href="/login">Se connecter</a>`}</p>
  `);
});

// ---------- Login / Logout ----------
app.get('/login', (req, res) => {
  res.send(`
    <h1>Login</h1>
    <form method="POST" action="/login">
      <label>username: <input name="username" required /></label><br/>
      <label>password: <input type="password" name="password" required /></label><br/>
      <button>Se connecter</button>
    </form>
  `);
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).send('username & password requis');
  const user = await findUserByUsername(username);
  if (!user) return res.status(401).send('Identifiants invalides');
  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.status(401).send('Identifiants invalides');
  req.session.regenerate(err => {
    if (err) return res.status(500).send('Erreur session');
    req.session.userId = user.id;
    req.session.admin = !!user.admin;
    res.redirect('/');
  });
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('sid');
    res.redirect('/');
  });
});

// ---------- SEARCH (validation, sanitization, journalisation)
app.post('/search', (req, res) => {
  logAccess(req, '/search');

  const qRaw = (req.body.q || '').trim();
  if (!qRaw) return res.status(400).send('<h3>Paramètre q requis</h3>');
  if (qRaw.length > 30) return res.status(400).send('<h3>q trop long (max 30 caractères)</h3>');

  const whitelist = /^[A-Za-z-]+$/;
  if (!whitelist.test(qRaw)) return res.status(400).send('<h3>q contient des caractères interdits. Lettres et tirets seulement.</h3>');

  const q = qRaw.toLowerCase();

  let allUsers = [];
  try {
    allUsers = fs.readFileSync(path.join(__dirname, 'data', 'users.txt'), 'utf8')
      .split(/\r?\n/).filter(Boolean);
  } catch (err) {
    return res.status(500).send('<h3>Erreur lecture users</h3>');
  }

  const hits = allUsers.filter(u => u.toLowerCase().includes(q));
  const MAX_RESULTS = 100;
  const limited = hits.slice(0, MAX_RESULTS).map(line => escapeHtml(line));

  res.send(`
    <h2>Résultats</h2>
    <p>Requête sécurisée (échappée) : <code>${escapeHtml(qRaw)}</code></p>
    <p>Affichage ${limited.length} résultat(s)${hits.length > MAX_RESULTS ? ` (sur ${hits.length} trouvés — affichage limité à ${MAX_RESULTS})` : ''}</p>
    <pre>${limited.join('\\n') || 'Aucun'}</pre>
  `);
});

// ---------- Admin ----------
app.get('/admin', requireAdmin, (req, res) => {
  logAccess(req, '/admin');
  res.send(`<h1>Console Admin</h1><p>Bienvenue, administrateur.</p>`);
});

// ---------- Flag ----------
app.get('/flag', requireAdmin, (req, res) => {
  logAccess(req, '/flag');
  const flagFile = path.join(__dirname, 'public', 'flag.txt');
  if (!fs.existsSync(flagFile)) return res.status(404).send('Flag introuvable.');
  res.download(flagFile, 'flag.txt', err => {
    if (err) res.status(500).send('Erreur lecture flag');
  });
});

// ---------- Start server ----------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Intranet demo listening on port ${PORT}`));
