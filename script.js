/* ======================== hash.js ======================== */
/* =============================================================
   hash.js — hachage des mots de passe (SHA-256 salé, itéré)
   Pourquoi : data/users.json est PUBLIC (tout le monde peut l'ouvrir).
   On n'y met donc jamais un mot de passe en clair, seulement { salt, hash }.
   Implémentation 100 % JavaScript : fonctionne aussi hors HTTPS / en fichier local.
   ============================================================= */
(function (root) {
  const K = new Uint32Array([
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2]);

  function sha256Hex(str) {
    const bytes = new TextEncoder().encode(str);
    const l = bytes.length, padded = ((l + 9 + 63) >> 6) << 6;
    const buf = new Uint8Array(padded); buf.set(bytes); buf[l] = 0x80;
    const dv = new DataView(buf.buffer);
    dv.setUint32(padded - 8, Math.floor((l * 8) / 0x100000000));
    dv.setUint32(padded - 4, (l * 8) >>> 0);
    const H = new Uint32Array([0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19]);
    const w = new Uint32Array(64);
    for (let off = 0; off < padded; off += 64) {
      for (let i = 0; i < 16; i++) w[i] = dv.getUint32(off + i * 4);
      for (let i = 16; i < 64; i++) {
        const a = w[i - 15], b = w[i - 2];
        const s0 = ((a >>> 7) | (a << 25)) ^ ((a >>> 18) | (a << 14)) ^ (a >>> 3);
        const s1 = ((b >>> 17) | (b << 15)) ^ ((b >>> 19) | (b << 13)) ^ (b >>> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
      }
      let a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
      for (let i = 0; i < 64; i++) {
        const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
        const ch = (e & f) ^ (~e & g);
        const t1 = (h + S1 + ch + K[i] + w[i]) | 0;
        const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
        const mj = (a & b) ^ (a & c) ^ (b & c);
        const t2 = (S0 + mj) | 0;
        h = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
      }
      H[0] += a; H[1] += b; H[2] += c; H[3] += d; H[4] += e; H[5] += f; H[6] += g; H[7] += h;
    }
    return Array.from(H, x => x.toString(16).padStart(8, "0")).join("");
  }

  const ROUNDS = 3000;
  function derive(password, salt) {
    let h = sha256Hex(salt + ":" + password);
    for (let i = 0; i < ROUNDS; i++) h = sha256Hex(h + salt);
    return h;
  }
  function randomHex(n) {
    const b = new Uint8Array(n);
    (root.crypto || {}).getRandomValues ? root.crypto.getRandomValues(b) : b.forEach((_, i) => b[i] = Math.floor(Math.random() * 256));
    return Array.from(b, x => x.toString(16).padStart(2, "0")).join("");
  }
  /* make("monmotdepasse") → { salt, hash } */
  function make(password) { const salt = randomHex(16); return { salt, hash: derive(password, salt) }; }
  /* verify("monmotdepasse", { salt, hash }) → true / false */
  function verify(password, cred) {
    if (!cred || typeof cred.salt !== "string" || typeof cred.hash !== "string") return false;
    const h = derive(password, cred.salt);
    let diff = h.length ^ cred.hash.length;
    for (let i = 0; i < h.length; i++) diff |= h.charCodeAt(i) ^ (cred.hash.charCodeAt(i) || 0);
    return diff === 0;
  }
  const API = { make, verify, sha256Hex };
  if (typeof module !== "undefined" && module.exports) module.exports = API; else root.Hash = API;
})(typeof window !== "undefined" ? window : globalThis);

/* ======================== config.js ======================== */
/* =============================================================
   config.js — réglages du site
   ============================================================= */

/* Fichier de données partagé (utilisateurs, mots de passe hachés, permissions).
   C'est CE fichier que tous les navigateurs lisent.
   Le site essaie dans l'ordre : users.json (à côté de index.html), puis data/users.json. */
const DATA_URLS = ["users.json", "data/users.json"];

/* Clés du localStorage (copie locale, propre à chaque navigateur) */
const STORE_KEY = "idosr2026_data";
const OLD_USERS_KEY = "idosr2026_users";          /* anciennes versions : migration automatique */

/* ---------- COURS DISPONIBLES ----------
   ➜ POUR AJOUTER UN COURS :
     1. Ajoutez une ligne ci-dessous (id unique, nom, icône, id du bloc <div class="layout"> et id de sa sidebar).
     2. Ajoutez la carte <div class="choice-card" data-target="VOTRE_ID"> dans la section CHOICE (même id).
     3. Ajoutez le module HTML (<div class="layout hidden" id="...App">) comme les autres.
     4. Ajoutez le module dans ALL_APPS plus bas et un bouton "Modules"/"Verrouiller" (voir fin du module).
   Le cours apparaîtra automatiquement dans les cases à cocher de l'Admin. */
const COURSES = [
  { id: "dns",       label: "DNS",           icon: "🌐", app: "dnsApp",       sidebar: "sidebarDns" },
  { id: "dhcp",      label: "DHCP",          icon: "📦", app: "dhcpApp",      sidebar: "sidebarDhcp" },
  { id: "ddns",      label: "DDNS",          icon: "🔗", app: "ddnsApp",      sidebar: "sidebarDdns" },
  { id: "secondary", label: "DNS SECONDARY", icon: "🛰️", app: "secondaryApp", sidebar: "sidebarSecondary" },
  /* Module déjà présent dans votre site (DHCP Relay) : conservé et gérable par l'Admin */
  { id: "relay",     label: "DHCP RELAY",    icon: "📡", app: "relayApp",     sidebar: "sidebarRelay" }
];

const VALID_IDS = COURSES.map(c => c.id);

/* Données de secours : utilisées UNIQUEMENT si data/users.json est introuvable
   (ex. page ouverte par double-clic en fichier local) et qu'aucune copie locale n'existe.
   Identifiants de départ : admin / maaroufi2026 · user1 / user123 · user2 / user456 */
const FALLBACK_DATA = {
  "version": 1,
  "updatedAt": 1767225600000,
  "admin": {
    "username": "admin",
    "salt": "a8f9d73a5b8a86d0217415240ac6a4cd",
    "hash": "233c05fec00a16efc5566f7b8c0e55131beac531c2c1bdfb7d4f5a90579a433a"
  },
  "users": [
    {
      "username": "user1",
      "name": "Utilisateur 1",
      "salt": "cc5f99cd41edc8fa8ead2e6e0ad45eb4",
      "hash": "9b312e95c61226b417359ee1750b64f2feae50f61faedea648ad75c058602f6a",
      "courses": [
        "dns",
        "ddns"
      ]
    },
    {
      "username": "user2",
      "name": "Utilisateur 2",
      "salt": "354e50a07037b37039a16d34684082b4",
      "hash": "faca6eb1e24b1e54920383066a99d7cbf2fcbc23e8944b82366ee370799702ed",
      "courses": [
        "dns"
      ]
    }
  ]
};

/* ======================== storage.js ======================== */
/* =============================================================
   storage.js — données partagées (data/users.json) + copie locale (localStorage)

   RÈGLE : "la version la plus récente gagne" (champ updatedAt).
   • Au chargement, on lit data/users.json (serveur) ET le localStorage (ce navigateur).
   • On garde celui dont updatedAt est le plus grand.
   • Quand l'Admin clique "Tout enregistrer" : sauvegarde dans le localStorage (updatedAt = maintenant).
   • Pour que les AUTRES navigateurs voient les changements : l'Admin exporte users.json
     et remplace data/users.json sur l'hébergement (GitHub / Netlify).
   ============================================================= */
const Store = (function () {
  let state = null;     /* données actives : { version, updatedAt, admin, users } */
  let remote = null;    /* dernière version lue sur le serveur (ou null) */
  let remoteOk = false; /* le fichier serveur a-t-il pu être lu ? */

  const clone = o => JSON.parse(JSON.stringify(o));
  const isCred = o => o && typeof o.salt === "string" && o.salt && typeof o.hash === "string" && o.hash;

  /* Vérifie / nettoie un objet de données. Retourne null s'il est invalide. */
  function normalize(d) {
    if (!d || typeof d !== "object" || !Array.isArray(d.users) || !d.admin) return null;
    if (typeof d.admin.username !== "string" || !isCred(d.admin)) return null;
    const seen = new Set(), users = [];
    for (const u of d.users) {
      if (!u || typeof u.username !== "string" || !isCred(u)) continue;
      const username = u.username.trim().toLowerCase();
      if (!username || seen.has(username)) continue;
      seen.add(username);
      users.push({
        username,
        name: (typeof u.name === "string" && u.name.trim()) ? u.name.trim() : username,
        salt: u.salt, hash: u.hash,
        courses: Array.isArray(u.courses) ? u.courses.filter(id => VALID_IDS.includes(id)) : []
      });
    }
    return {
      version: 1,
      updatedAt: Number(d.updatedAt) || 0,
      admin: { username: d.admin.username.trim().toLowerCase(), salt: d.admin.salt, hash: d.admin.hash },
      users
    };
  }

  function readLocal() {
    try { return normalize(JSON.parse(localStorage.getItem(STORE_KEY))); } catch (e) { return null; }
  }
  function writeLocal(d) {
    try { localStorage.setItem(STORE_KEY, JSON.stringify(d)); return true; } catch (e) { return false; }
  }
  async function fetchRemote() {
    for (const url of DATA_URLS) {
      try {
        const r = await fetch(url + "?t=" + Date.now(), { cache: "no-store" });
        if (!r.ok) continue;
        const d = normalize(await r.json());
        if (d) return d;
      } catch (e) { /* on essaie l'adresse suivante */ }
    }
    return null;
  }

  /* Migration depuis l'ancienne version (mots de passe en clair dans idosr2026_users) */
  function migrateOld(adminCred) {
    try {
      const raw = localStorage.getItem(OLD_USERS_KEY);
      if (!raw) return null;
      const arr = JSON.parse(raw);
      if (!Array.isArray(arr)) return null;
      const users = arr.filter(u => u && typeof u.username === "string" && typeof u.password === "string")
        .map(u => ({ username: u.username, name: u.name, ...Hash.make(u.password), courses: u.courses }));
      localStorage.removeItem(OLD_USERS_KEY);   /* on supprime les mots de passe en clair */
      return normalize({ updatedAt: Date.now(), admin: adminCred, users });
    } catch (e) { return null; }
  }

  async function init() {
    remote = await fetchRemote();
    remoteOk = !!remote;
    let local = readLocal();
    if (!local) {
      local = migrateOld((remote || normalize(FALLBACK_DATA)).admin);
      if (local) writeLocal(local);
    }
    if (remote && (!local || remote.updatedAt >= local.updatedAt)) {
      state = clone(remote);
      writeLocal(state);                 /* copie locale = serveur */
    } else if (local) {
      state = local;                     /* modifications locales plus récentes que le serveur */
    } else {
      state = normalize(FALLBACK_DATA);  /* serveur illisible + rien en local */
      writeLocal(state);
    }
    return state;
  }

  /* Enregistre de nouvelles données (utilisées par l'Admin). Retourne true si le localStorage a réussi. */
  function commit(admin, users) {
    state = normalize({ updatedAt: Math.max(Date.now(), state.updatedAt + 1), admin, users });
    return writeLocal(state);
  }

  /* 'published' : identique au serveur · 'unpublished' : modifs locales non publiées · 'noserver' : serveur illisible */
  function status() {
    if (!remoteOk) return "noserver";
    return remote.updatedAt >= state.updatedAt ? "published" : "unpublished";
  }

  /* Abandonne les données locales et recharge celles du serveur. */
  async function resetFromServer() {
    const r = await fetchRemote();
    if (!r) return false;
    remote = r; remoteOk = true; state = clone(r);
    writeLocal(state);
    return true;
  }

  /* Lit un fichier users.json importé par l'Admin. Retourne les données ou null. */
  function parseImport(text) {
    try { return normalize(JSON.parse(text)); } catch (e) { return null; }
  }

  /* Télécharge les données actives sous forme de users.json */
  function download() {
    const blob = new Blob([JSON.stringify(state, null, 2) + "\n"], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob); a.download = "users.json";
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  }

  /* Un autre onglet du même navigateur a enregistré : on recharge */
  function onExternalChange(cb) {
    window.addEventListener("storage", e => {
      if (e.key !== STORE_KEY) return;
      const d = readLocal();
      if (d) { state = d; cb(); }
    });
  }

  return { init, get: () => state, commit, status, resetFromServer, parseImport, download, onExternalChange, clone };
})();

/* ======================== app.js ======================== */
/* =============================================================
   app.js — connexion, panneau Admin, panneau Utilisateur, navigation
   Dépend de : hash.js, config.js, storage.js
   ============================================================= */

/* Données actives (copie en lecture seule utilisée pour la connexion) */
let USERS = [];          /* utilisateurs ENREGISTRÉS */
let ADMIN_CRED = null;   /* compte admin : { username, salt, hash } */
const cloneUsers = o => JSON.parse(JSON.stringify(o));
function syncFromStore() {
  const s = Store.get();
  USERS = cloneUsers(s.users);
  ADMIN_CRED = cloneUsers(s.admin);
}
function coursesOf(user) {
  return (user.courses || []).filter(id => VALID_IDS.includes(id));
}

/* ---------- Références DOM ---------- */
const gate     = document.getElementById('gate');
const gateBox  = document.getElementById('gateBox');
const gateForm = document.getElementById('gateForm');
const gateUser = document.getElementById('gateUser');
const gatePass = document.getElementById('gatePass');
const gateMsg  = document.getElementById('gateMsg');

const choice       = document.getElementById('choice');       /* = Panneau Utilisateur */
const adminPanel   = document.getElementById('adminPanel');
const dnsApp       = document.getElementById('dnsApp');
const relayApp     = document.getElementById('relayApp');
const secondaryApp = document.getElementById('secondaryApp');
const dhcpApp      = document.getElementById('dhcpApp');
const ddnsApp      = document.getElementById('ddnsApp');

const ALL_APPS = [dnsApp, relayApp, secondaryApp, dhcpApp, ddnsApp];

/* Le contenu des cours N'EST PAS dans la page tant que l'utilisateur n'y a pas droit :
   on retire tous les modules du DOM au chargement (fin du script), puis on n'insère que les modules autorisés. */
/* (le retrait effectif du DOM est fait tout en bas du script, après l'attache des boutons) */
const SCRIPT_TAG = document.querySelector('body > script');
function mountApps(allowedIds) {
  COURSES.forEach(c => {
    const el = document.getElementById(c.app) || ALL_APPS.find(a => a.id === c.app);
    if (allowedIds.includes(c.id) && !el.isConnected) document.body.insertBefore(el, SCRIPT_TAG);
  });
}
function unmountApps() { ALL_APPS.forEach(a => { a.classList.add('hidden'); a.remove(); }); }

/* ---------- Session (en mémoire : un rechargement redemande le login) ---------- */
let session = null;   /* { role: 'admin' | 'user', user } */

function hideAllViews() {
  gate.classList.add('hidden');
  choice.classList.add('hidden');
  adminPanel.classList.add('hidden');
  ALL_APPS.forEach(a => a.classList.add('hidden'));
}

/* ---------- Chargement des données (serveur + localStorage) ---------- */
gateMsg.style.color = 'var(--muted)';
gateMsg.textContent = "⏳ Chargement des données...";
const dataReady = Store.init().then(() => {
  syncFromStore();
  gateMsg.textContent = ""; gateMsg.style.color = "";
}).catch(() => {
  gateMsg.style.color = "";
  gateMsg.textContent = "⚠ Erreur de chargement des données";
});

/* ---------- Login ---------- */
gateForm.addEventListener('submit', async function (e) {
  e.preventDefault();
  await dataReady;
  if (!ADMIN_CRED) return;
  const u = gateUser.value.trim().toLowerCase();
  const p = gatePass.value;

  if (u === ADMIN_CRED.username && Hash.verify(p, ADMIN_CRED)) {
    session = { role: 'admin', user: { username: ADMIN_CRED.username, name: 'Administrateur' } };
    work = cloneUsers(USERS); workAdmin = cloneUsers(ADMIN_CRED);   /* copie de travail : Admin uniquement */
    gateMsg.textContent = "";
    showAdminPanel();
    return;
  }
  const found = USERS.find(x => x.username === u);
  if (Hash.verify(p, found || { salt: "x", hash: "x" }) && found) {
    session = { role: 'user', user: found };
    gateMsg.textContent = "";
    showUserPanel();
    return;
  }
  gateMsg.textContent = "❌ Identifiant ou mot de passe incorrect";
  gatePass.value = "";
  gatePass.focus();
  gateBox.classList.remove('shake');
  void gateBox.offsetWidth;
  gateBox.classList.add('shake');
});

/* ============================================================= */
/* ============ PANNEAU ADMIN : GESTION DES UTILISATEURS ======== */
/* ============================================================= */
const byId = id => document.getElementById(id);
const userListEl = byId('userList'), permListEl = byId('permList'), permTitle = byId('permTitle');
const userDetail = byId('userDetail'), userEmpty = byId('userEmpty'), userCount = byId('userCount');
const fName = byId('fName'), fUser = byId('fUser'), fPass = byId('fPass');
const profileMsg = byId('profileMsg'), passMsg = byId('passMsg'), saveMsg = byId('saveMsg');
const saveBar = byId('saveBar'), dirtyNote = byId('dirtyNote');
const saveAllBtn = byId('saveAll'), discardBtn = byId('discardAll');

let work = null;          /* copie de travail des utilisateurs (modifications NON enregistrées) */
let workAdmin = null;     /* copie de travail du compte admin */
let selectedKey = null;   /* username de l'utilisateur sélectionné */

/* 🔒 Toute action de gestion passe par ce contrôle : seul l'Admin connecté peut modifier les comptes */
function requireAdmin() { return !!(session && session.role === 'admin' && work); }
function isDirty() { return !!work && JSON.stringify([workAdmin, work]) !== JSON.stringify([ADMIN_CRED, USERS]); }
function currentUser() { return work ? (work.find(u => u.username === selectedKey) || null) : null; }
function flash(el, text, ok) {
  el.textContent = text;
  el.className = 'form-msg ' + (ok ? 'ok' : 'err');
  clearTimeout(el._t);
  el._t = setTimeout(() => { el.textContent = ''; }, 3500);
}

/* ---------- Validation ---------- */
const USER_RE = /^[a-z0-9._-]{3,20}$/;
function validateUsername(raw, ignoreKey) {
  const u = String(raw).trim().toLowerCase();
  if (!USER_RE.test(u)) return { err: "Identifiant : 3 à 20 caractères (lettres, chiffres, . _ -)" };
  if (u === workAdmin.username) return { err: "Cet identifiant est réservé" };
  if (work.some(x => x.username === u && x.username !== ignoreKey)) return { err: "Cet identifiant existe déjà" };
  return { value: u };
}
function validatePassword(p) { return p.length < 6 ? "Mot de passe : 6 caractères minimum" : null; }
function randomPassword() {
  const chars = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const buf = new Uint32Array(10); crypto.getRandomValues(buf);
  return Array.from(buf, n => chars[n % chars.length]).join("");
}

/* ---------- Affichage ---------- */
function showAdminPanel() {
  if (!session || session.role !== 'admin') return;   /* un utilisateur normal ne voit jamais ce panneau */
  hideAllViews();
  unmountApps();
  if (!work) { work = cloneUsers(USERS); workAdmin = cloneUsers(ADMIN_CRED); }
  if (!currentUser()) selectedKey = work.length ? work[0].username : null;
  adminPanel.classList.remove('hidden');
  renderAdmin();
  window.scrollTo(0, 0);
}
function renderAdmin() { renderList(); renderDetail(); renderSaveBar(); renderData(); }

function renderList() {
  userListEl.innerHTML = "";
  userCount.textContent = "(" + work.length + ")";
  work.forEach(u => {
    const b = document.createElement('button');
    b.type = 'button';
    b.className = 'user-item' + (u.username === selectedKey ? ' active' : '');
    const av = document.createElement('span'); av.className = 'avatar'; av.textContent = (u.name || u.username).charAt(0).toUpperCase();
    const tx = document.createElement('span'); tx.textContent = u.name;
    const sm = document.createElement('small'); sm.textContent = '@' + u.username + ' · ' + coursesOf(u).length + ' cours';
    tx.appendChild(sm);
    b.append(av, tx);
    b.addEventListener('click', () => { selectedKey = u.username; renderAdmin(); });
    userListEl.appendChild(b);
  });
}
function renderDetail() {
  const u = currentUser();
  userDetail.classList.toggle('hidden', !u);
  userEmpty.classList.toggle('hidden', !!u);
  if (!u) return;
  fName.value = u.name; fUser.value = u.username;
  fPass.value = ""; fPass.type = 'password';
  profileMsg.textContent = ""; passMsg.textContent = "";
  renderPerms();
}
function renderSaveBar() {
  const d = isDirty();
  saveBar.classList.toggle('dirty', d);
  dirtyNote.textContent = d ? "● Modifications non enregistrées" : "✔ Tout est enregistré";
  saveAllBtn.disabled = !d;
  discardBtn.disabled = !d;
}
function renderPerms() {
  const u = currentUser(); if (!u) return;
  permTitle.textContent = "Accès aux cours de " + u.name;
  permListEl.innerHTML = "";
  COURSES.forEach(c => {
    const on = u.courses.includes(c.id);
    const lab = document.createElement('label');
    lab.className = 'perm-item' + (on ? ' on' : '');
    const cb = document.createElement('input'); cb.type = 'checkbox'; cb.checked = on;
    const ico = document.createElement('span'); ico.className = 'ico'; ico.textContent = c.icon;
    const lbl = document.createElement('span'); lbl.className = 'lbl'; lbl.textContent = c.label;
    const st  = document.createElement('span'); st.className = 'st'; st.textContent = on ? 'ACTIVÉ' : 'DÉSACTIVÉ';
    cb.addEventListener('change', () => {
      if (!requireAdmin()) return;
      const i = u.courses.indexOf(c.id);
      if (cb.checked && i < 0) u.courses.push(c.id);
      if (!cb.checked && i >= 0) u.courses.splice(i, 1);
      lab.classList.toggle('on', cb.checked);
      st.textContent = cb.checked ? 'ACTIVÉ' : 'DÉSACTIVÉ';
      renderList(); renderSaveBar();
    });
    lab.append(cb, ico, lbl, st);
    permListEl.appendChild(lab);
  });
}

/* ---------- Fenêtre modale ---------- */
const modal = byId('modal'), modalMsg = byId('modalMsg'), modalOk = byId('modalOk');
let modalHandler = null;
function openModal(o) {
  byId('modalTitle').textContent = o.title;
  const body = byId('modalBody'); body.innerHTML = "";
  if (o.html) body.innerHTML = o.html;                      /* HTML statique uniquement (aucune donnée saisie) */
  if (o.text) { const p = document.createElement('p'); p.textContent = o.text; body.appendChild(p); }
  modalMsg.textContent = "";
  modalOk.textContent = o.okLabel || "OK";
  modalOk.className = 'btn primary' + (o.danger ? ' danger-fill' : '');
  modalHandler = o.onOk;
  modal.classList.remove('hidden');
  const first = body.querySelector('input');
  (first || modalOk).focus();
  if (o.onOpen) o.onOpen(body);
}
function closeModal() { modal.classList.add('hidden'); modalHandler = null; }
modalOk.addEventListener('click', () => {
  if (!requireAdmin()) { closeModal(); return; }
  const err = modalHandler ? modalHandler() : null;
  if (err) { modalMsg.textContent = err; return; }
  closeModal();
});
byId('modalCancel').addEventListener('click', closeModal);
modal.addEventListener('mousedown', e => { if (e.target === modal) closeModal(); });
modal.addEventListener('keydown', e => {
  if (e.key === 'Escape') closeModal();
  if (e.key === 'Enter' && e.target.tagName === 'INPUT') { e.preventDefault(); modalOk.click(); }
});

/* ➕ Ajouter un utilisateur */
byId('addUserBtn').addEventListener('click', () => {
  if (!requireAdmin()) return;
  openModal({
    title: "➕ Nouvel utilisateur",
    okLabel: "Ajouter",
    html:
      '<label class="field">Nom affiché<input type="text" id="mName" maxlength="40" autocomplete="off"></label>' +
      '<label class="field">Nom d\'utilisateur<input type="text" id="mUser" maxlength="20" autocomplete="off" autocapitalize="none" spellcheck="false"></label>' +
      '<label class="field">Mot de passe<span class="pw-row"><input type="text" id="mPass" autocomplete="new-password" spellcheck="false">' +
      '<button class="btn" id="mGen" type="button">🎲 Générer</button></span></label>',
    onOpen: () => { byId('mGen').addEventListener('click', () => { byId('mPass').value = randomPassword(); }); },
    onOk: () => {
      const name = byId('mName').value.trim();
      const v = validateUsername(byId('mUser').value, null);
      const pw = byId('mPass').value;
      if (!name) return "Le nom ne peut pas être vide";
      if (v.err) return v.err;
      const pe = validatePassword(pw); if (pe) return pe;
      work.push({ username: v.value, name: name, ...Hash.make(pw), courses: [] });
      selectedKey = v.value;
      renderAdmin();
      flash(saveMsg, "✔ Utilisateur ajouté (pensez à enregistrer)", true);
      return null;
    }
  });
});

/* ✏️ Modifier le nom / l'identifiant */
byId('applyProfile').addEventListener('click', () => {
  if (!requireAdmin()) return;
  const u = currentUser(); if (!u) return;
  const name = fName.value.trim();
  if (!name) { flash(profileMsg, "Le nom ne peut pas être vide", false); return; }
  const v = validateUsername(fUser.value, u.username);
  if (v.err) { flash(profileMsg, v.err, false); return; }
  u.name = name; u.username = v.value; selectedKey = v.value;
  fUser.value = v.value;
  permTitle.textContent = "Accès aux cours de " + u.name;
  renderList(); renderSaveBar();
  flash(profileMsg, "✔ Modifié (pensez à enregistrer)", true);
});

/* 🔑 Changer / réinitialiser le mot de passe */
byId('togglePass').addEventListener('click', () => { fPass.type = fPass.type === 'password' ? 'text' : 'password'; });
byId('genPass').addEventListener('click', () => { fPass.value = randomPassword(); fPass.type = 'text'; fPass.focus(); });
byId('applyPass').addEventListener('click', () => {
  if (!requireAdmin()) return;
  const u = currentUser(); if (!u) return;
  const pw = fPass.value;
  const pe = validatePassword(pw);
  if (pe) { flash(passMsg, pe, false); return; }
  Object.assign(u, Hash.make(pw));   /* on ne garde jamais le mot de passe en clair */
  fPass.value = ""; fPass.type = 'password';
  renderSaveBar();
  flash(passMsg, "✔ Mot de passe changé (pensez à enregistrer)", true);
});

/* Cases à cocher des cours */
byId('checkAll').addEventListener('click', () => {
  if (!requireAdmin()) return; const u = currentUser(); if (!u) return;
  u.courses = VALID_IDS.slice(); renderPerms(); renderList(); renderSaveBar();
});
byId('uncheckAll').addEventListener('click', () => {
  if (!requireAdmin()) return; const u = currentUser(); if (!u) return;
  u.courses = []; renderPerms(); renderList(); renderSaveBar();
});

/* 🗑️ Supprimer */
byId('deleteUser').addEventListener('click', () => {
  if (!requireAdmin()) return;
  const u = currentUser(); if (!u) return;
  openModal({
    title: "🗑️ Supprimer l'utilisateur",
    okLabel: "Supprimer",
    danger: true,
    text: "Supprimer « " + u.name + " » (@" + u.username + ") ? Le compte sera retiré dès l'enregistrement.",
    onOk: () => {
      const i = work.findIndex(x => x.username === u.username);
      if (i >= 0) work.splice(i, 1);
      selectedKey = work.length ? work[Math.min(i, work.length - 1)].username : null;
      renderAdmin();
      flash(saveMsg, "Utilisateur supprimé (pensez à enregistrer)", true);
      return null;
    }
  });
});

/* 💾 Tout enregistrer → localStorage (+ updatedAt) */
saveAllBtn.addEventListener('click', () => {
  if (!requireAdmin() || !isDirty()) return;
  const ok = Store.commit(workAdmin, work);
  syncFromStore();                       /* la connexion utilise désormais la nouvelle liste */
  work = cloneUsers(USERS); workAdmin = cloneUsers(ADMIN_CRED);
  renderSaveBar(); renderData();
  flash(saveMsg, ok ? "✔ Modifications enregistrées" : "⚠ Appliqué pour cette session seulement (stockage du navigateur bloqué)", ok);
});
/* ↩ Annuler les modifications non enregistrées */
discardBtn.addEventListener('click', () => {
  if (!requireAdmin() || !isDirty()) return;
  openModal({
    title: "↩ Annuler les modifications",
    okLabel: "Annuler les modifications",
    danger: true,
    text: "Toutes les modifications non enregistrées seront perdues.",
    onOk: () => { work = cloneUsers(USERS); workAdmin = cloneUsers(ADMIN_CRED); renderAdmin(); return null; }
  });
});


/* ---------- Données : statut, export / import, mot de passe admin ---------- */
const dataStatus = byId('dataStatus'), dataMsg = byId('dataMsg');
const fAdminPass = byId('fAdminPass'), adminPassMsg = byId('adminPassMsg'), importFile = byId('importFile');

function renderData() {
  const st = Store.status();
  const map = {
    published:   ["ok",   "✔ Synchronisé avec le fichier serveur data/users.json."],
    unpublished: ["warn", "💾 Enregistré dans CE navigateur, mais pas encore publié. Exportez users.json puis remplacez data/users.json sur l'hébergement pour que les autres navigateurs voient ces changements."],
    noserver:    ["warn", "⚠ Fichier serveur data/users.json introuvable : les données sont uniquement locales à ce navigateur."]
  }[st];
  dataStatus.className = 'data-status ' + map[0];
  dataStatus.textContent = map[1];
}
byId('exportBtn').addEventListener('click', () => {
  if (!requireAdmin()) return;
  if (isDirty()) { flash(dataMsg, "Cliquez d'abord sur 💾 Tout enregistrer, puis exportez.", false); return; }
  Store.download();
  flash(dataMsg, "✔ users.json téléchargé : remplacez data/users.json sur l'hébergement.", true);
});
byId('importBtn').addEventListener('click', () => { if (requireAdmin()) importFile.click(); });
importFile.addEventListener('change', async () => {
  const f = importFile.files && importFile.files[0];
  importFile.value = "";
  if (!f || !requireAdmin()) return;
  const imp = Store.parseImport(await f.text());
  if (!imp) { flash(dataMsg, "⚠ Fichier invalide (format users.json attendu).", false); return; }
  openModal({
    title: "⬆ Importer users.json",
    okLabel: "Importer",
    danger: true,
    text: "Ce fichier contient " + imp.users.length + " utilisateur(s). Il remplacera TOUS les utilisateurs et le mot de passe admin actuels (après enregistrement).",
    onOk: () => {
      work = imp.users; workAdmin = imp.admin;
      selectedKey = work.length ? work[0].username : null;
      renderAdmin();
      flash(dataMsg, "✔ Fichier importé (cliquez sur 💾 Tout enregistrer pour valider)", true);
      return null;
    }
  });
});
byId('reloadBtn').addEventListener('click', () => {
  if (!requireAdmin()) return;
  openModal({
    title: "↺ Recharger depuis le serveur",
    okLabel: "Recharger",
    danger: true,
    text: "Les données de ce navigateur seront remplacées par celles de data/users.json (modifications locales perdues).",
    onOk: () => {
      Store.resetFromServer().then(ok => {
        if (!requireAdmin()) return;
        if (!ok) { flash(dataMsg, "⚠ Impossible de lire data/users.json sur le serveur.", false); return; }
        syncFromStore();
        work = cloneUsers(USERS); workAdmin = cloneUsers(ADMIN_CRED);
        if (!currentUser()) selectedKey = work.length ? work[0].username : null;
        renderAdmin();
        flash(dataMsg, "✔ Données rechargées depuis le serveur", true);
      });
      return null;
    }
  });
});
byId('applyAdminPass').addEventListener('click', () => {
  if (!requireAdmin()) return;
  const pw = fAdminPass.value;
  if (pw.length < 8) { flash(adminPassMsg, "Mot de passe admin : 8 caractères minimum", false); return; }
  workAdmin = { username: workAdmin.username, ...Hash.make(pw) };
  fAdminPass.value = "";
  renderSaveBar();
  flash(adminPassMsg, "✔ Mot de passe admin changé (pensez à enregistrer)", true);
});

/* Déconnexion (avec avertissement s'il reste des modifications) */
byId('adminLogout').addEventListener('click', () => {
  if (!isDirty()) { lock(); return; }
  openModal({
    title: "🔒 Déconnexion",
    okLabel: "Quitter sans enregistrer",
    danger: true,
    text: "Des modifications ne sont pas enregistrées. Elles seront perdues si vous quittez.",
    onOk: () => { lock(); return null; }
  });
});
window.addEventListener('beforeunload', e => { if (session && session.role === 'admin' && isDirty()) { e.preventDefault(); e.returnValue = ''; } });
document.getElementById('adminViewCourses').addEventListener('click', showUserPanel);
document.getElementById('backToAdmin').addEventListener('click', showAdminPanel);

/* ============================================================= */
/* ====================== PANNEAU UTILISATEUR =================== */
/* ============================================================= */
const rolePill = document.getElementById('rolePill');
const whoName  = document.getElementById('whoName');

/* On mémorise le contenu d'origine de chaque carte pour pouvoir la restaurer / la verrouiller */
const CARD_ORIGINAL = {};
document.querySelectorAll('.choice-card').forEach(card => {
  card.dataset.course = card.dataset.target;
  CARD_ORIGINAL[card.dataset.course] = { html: card.innerHTML, cls: card.className };
});

function allowedIds() {
  if (!session) return [];
  return session.role === 'admin' ? VALID_IDS.slice() : coursesOf(session.user);
}

function showUserPanel() {
  hideAllViews();
  unmountApps();
  const allowed = allowedIds();
  const isAdmin = session.role === 'admin';

  rolePill.className = 'role-pill ' + (isAdmin ? 'admin' : 'user');
  rolePill.textContent = isAdmin ? '👑 Admin' : '👤 Utilisateur';
  whoName.textContent = session.user.name;
  document.getElementById('backToAdmin').classList.toggle('hidden', !isAdmin);

  document.querySelectorAll('.choice-card').forEach(card => {
    const id = card.dataset.course, orig = CARD_ORIGINAL[id];
    const course = COURSES.find(c => c.id === id);
    if (allowed.includes(id)) {
      card.className = orig.cls; card.innerHTML = orig.html; card.dataset.target = id;
    } else {
      /* Carte VERROUILLÉE : aucun contenu du cours n'est affiché */
      card.className = orig.cls + ' locked';
      card.removeAttribute('data-target');
      card.innerHTML = '<div class="choice-icon">🔒</div><h2></h2>' +
        '<p>Ce cours n\'est pas activé pour votre compte.</p><span class="lock-note">Accès verrouillé par l\'administrateur</span>';
      card.querySelector('h2').textContent = course ? course.label : id;
    }
  });
  mountApps(allowed);
  choice.classList.remove('hidden');
  window.scrollTo(0, 0);
}

/* ---------- Choix du module (délégation d'événement) ---------- */
document.querySelector('.choice-cards').addEventListener('click', function (e) {
  const card = e.target.closest('.choice-card');
  if (!card || card.classList.contains('locked')) return;
  openCourse(card.dataset.target);
});
function openCourse(id) {
  const course = COURSES.find(c => c.id === id);
  /* Double contrôle des droits avant d'afficher le moindre contenu */
  if (!course || !session || !allowedIds().includes(id)) return;
  hideAllViews();
  const app = document.getElementById(course.app);
  if (!app) return;
  app.classList.remove('hidden');
  initSidebar(course.sidebar);
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

/* ---------- Retour aux modules ---------- */
function goHome() { if (session) showUserPanel(); }
document.getElementById('homeFromDns').addEventListener('click', goHome);
document.getElementById('homeFromRelay').addEventListener('click', goHome);
document.getElementById('homeFromSecondary').addEventListener('click', goHome);
document.getElementById('homeFromDhcp').addEventListener('click', goHome);
document.getElementById('homeFromDdns').addEventListener('click', goHome);

/* ---------- Déconnexion / Verrouiller ---------- */
function lock() {
  session = null;
  work = null; workAdmin = null; selectedKey = null;
  if (typeof closeModal === 'function') closeModal();
  hideAllViews();
  unmountApps();
  gate.classList.remove('hidden');
  gateUser.value = "";
  gatePass.value = "";
  gateMsg.textContent = "";
  gateUser.focus();
}
document.getElementById('logoutBtn').addEventListener('click', lock);
document.getElementById('lockFromDns').addEventListener('click', lock);
document.getElementById('lockFromRelay').addEventListener('click', lock);
document.getElementById('lockFromSecondary').addEventListener('click', lock);
document.getElementById('lockFromDhcp').addEventListener('click', lock);
document.getElementById('lockFromDdns').addEventListener('click', lock);

/* ================= COPIER ================= */
document.querySelectorAll('.term').forEach(function (term) {
  const btn = term.querySelector('.copy-btn');
  if (!btn) return;
  btn.addEventListener('click', function () {
    const body = term.querySelector('.term-body');
    const cmds = body.querySelectorAll('.cmd');
    const text = cmds.length
      ? Array.from(cmds).map(c => c.textContent).join('\n')
      : body.innerText;
    navigator.clipboard.writeText(text).then(function () {
      btn.textContent = "✓ Copié";
      btn.classList.add('done');
      setTimeout(function () {
        btn.textContent = "Copier";
        btn.classList.remove('done');
      }, 1500);
    }).catch(function () {
      btn.textContent = "Erreur";
      setTimeout(function () { btn.textContent = "Copier"; }, 1500);
    });
  });
});

/* ================= SOMMAIRE ACTIF ================= */
function initSidebar(sidebarId) {
  const sidebar = document.getElementById(sidebarId);
  if (!sidebar) return;
  const links = Array.from(sidebar.querySelectorAll('a'));
  const sections = links
    .map(a => document.querySelector(a.getAttribute('href')))
    .filter(Boolean);
  if (!sections.length) return;

  const observer = new IntersectionObserver(function (entries) {
    entries.forEach(function (entry) {
      if (entry.isIntersecting) {
        links.forEach(l => l.classList.remove('active'));
        const active = links.find(l => l.getAttribute('href') === '#' + entry.target.id);
        if (active) active.classList.add('active');
      }
    });
  }, { rootMargin: "-15% 0px -70% 0px", threshold: 0 });

  sections.forEach(s => observer.observe(s));
}

/* ============ SÉCURITÉ : retirer TOUS les modules du DOM au chargement ============
   (les boutons ci-dessus sont déjà reliés ; les modules ne seront réinsérés qu'après login, selon les permissions) */
ALL_APPS.forEach(a => a.remove());

/* ============ Synchronisation entre onglets du même navigateur ============ */
Store.onExternalChange(() => {
  const wasDirty = isDirty();
  const prevCourses = (session && session.role === 'user') ? JSON.stringify(coursesOf(session.user)) : null;
  syncFromStore();
  if (!session) return;
  if (session.role === 'admin') {
    if (!wasDirty) {                       /* pas de modifs en cours : on affiche la nouvelle version */
      work = cloneUsers(USERS); workAdmin = cloneUsers(ADMIN_CRED);
      if (!adminPanel.classList.contains('hidden')) {
        if (!currentUser()) selectedKey = work.length ? work[0].username : null;
        renderAdmin();
      }
    }
    return;
  }
  const me = USERS.find(x => x.username === session.user.username);
  if (!me) { lock(); gateMsg.textContent = "Votre compte a été modifié ou supprimé. Reconnectez-vous."; return; }
  session.user = me;
  if (JSON.stringify(coursesOf(me)) !== prevCourses) showUserPanel();   /* permissions changées → retour à la liste des cours */
});

