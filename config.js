/* =============================================================
   config.js — réglages du site
   ============================================================= */

/* Fichier de données partagé (utilisateurs, mots de passe hachés, permissions).
   C'est CE fichier que tous les navigateurs lisent. */
const DATA_URL  = "data/users.json";

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
