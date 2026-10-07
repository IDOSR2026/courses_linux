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
    try {
      const r = await fetch(DATA_URL + "?t=" + Date.now(), { cache: "no-store" });
      if (!r.ok) return null;
      return normalize(await r.json());
    } catch (e) { return null; }
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
