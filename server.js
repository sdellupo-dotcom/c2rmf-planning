/**
 * C2RMF — Planification des interventions
 * Serveur applicatif : API REST + sessions + rôles + frontend statique.
 *
 * Commandes :
 *   node server.js migrate       -> crée / met à jour les tables PostgreSQL
 *   node server.js create-admin  -> crée interactivement le premier administrateur
 *   node server.js               -> démarre le serveur HTTP
 *
 * Variables d'environnement :
 *   DATABASE_URL   (requis)  ex. postgres://user:pass@localhost:5432/c2rmf_planning
 *   SESSION_SECRET (requis)  chaîne aléatoire longue (ex. `openssl rand -hex 32`)
 *   PORT           (défaut 3000)
 *   COOKIE_SECURE  mettre à true si le site est servi derrière HTTPS
 *   TRUST_PROXY    mettre à true si le site est derrière nginx/Apache (req.ip réel)
 */

const path = require("path");
const readline = require("readline");
const express = require("express");
const session = require("express-session");
const argon2 = require("argon2");
const pg = require("pg");
const ConnectPgSimple = require("connect-pg-simple");

/* ------------------------------------------------------------------ */
/* Configuration                                                       */
/* ------------------------------------------------------------------ */

const PORT = Number(process.env.PORT || 3000);
// Version revue : login repare, dates coherentes, validation des saisies, anti-force brute.
const DATABASE_URL = process.env.DATABASE_URL;
const SESSION_SECRET = process.env.SESSION_SECRET;
const COOKIE_SECURE = process.env.COOKIE_SECURE === "true";
const TRUST_PROXY = process.env.TRUST_PROXY === "true";

if (!DATABASE_URL) {
  console.error("Erreur : la variable d'environnement DATABASE_URL est requise.");
  process.exit(1);
}
if (!SESSION_SECRET) {
  console.error("Erreur : la variable d'environnement SESSION_SECRET est requise.");
  process.exit(1);
}

const ROLES = ["admin", "gestionnaire", "visiteur"];
const MESURES = [
  "proxyclick",
  "visite_prevention",
  "plan_prevention",
  "registre_securite",
  "protocole_prevenance",
];
const MAX_VARCHAR = 255;

const pool = new pg.Pool({ connectionString: DATABASE_URL });

/* ------------------------------------------------------------------ */
/* Schéma de base de données                                           */
/* ------------------------------------------------------------------ */

const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS users (
  id            SERIAL PRIMARY KEY,
  email         VARCHAR(255) NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  nom           VARCHAR(255) NOT NULL,
  service       VARCHAR(255) NOT NULL DEFAULT '-',
  role          VARCHAR(20)  NOT NULL CHECK (role IN ('admin','gestionnaire','visiteur')),
  created_at    TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS interventions (
  id                  SERIAL PRIMARY KEY,
  date                DATE NOT NULL,
  batiment            VARCHAR(255) NOT NULL,
  type                VARCHAR(255) NOT NULL,
  horaires            VARCHAR(255) NOT NULL DEFAULT '',
  hote                VARCHAR(255) NOT NULL DEFAULT '',
  proxyclick          BOOLEAN      NOT NULL DEFAULT FALSE,
  visite_prevention   BOOLEAN      NOT NULL DEFAULT FALSE,
  plan_prevention     BOOLEAN      NOT NULL DEFAULT FALSE,
  registre_securite   BOOLEAN      NOT NULL DEFAULT FALSE,
  protocole_prevenance BOOLEAN     NOT NULL DEFAULT FALSE,
  observations        TEXT         NOT NULL DEFAULT '',
  cree_par            INTEGER      NOT NULL REFERENCES users(id),
  created_at          TIMESTAMPTZ  NOT NULL DEFAULT now(),
  updated_at          TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_interventions_date ON interventions (date);

-- Table utilisée par connect-pg-simple (stockage des sessions dans PostgreSQL)
CREATE TABLE IF NOT EXISTS session (
  sid    VARCHAR(255) PRIMARY KEY,
  sess   JSON         NOT NULL,
  expire TIMESTAMP(6) NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_session_expire ON session (expire);
`;

/* ------------------------------------------------------------------ */
/* CLI : migration et création du premier administrateur               */
/* ------------------------------------------------------------------ */

async function migrer() {
  await pool.query(SCHEMA_SQL);
  console.log("Base de données initialisée / à jour (users, interventions, session).");
  await pool.end();
}

function question(rl, texte) {
  return new Promise((resolve) => rl.question(texte, resolve));
}

async function creerAdmin() {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });
  try {
    console.log("--- Création du compte administrateur ---");
    const email = String(await question(rl, "Email : ")).trim().toLowerCase();
    const nom = String(await question(rl, "Nom complet : ")).trim();
    const service = String(await question(rl, "Service (optionnel) : ")).trim() || "-";
    const mdp1 = String(await question(rl, "Mot de passe : ")).trim();
    const mdp2 = String(await question(rl, "Confirmation du mot de passe : ")).trim();

    if (!email || !nom || !mdp1) {
      console.error("Email, nom et mot de passe sont obligatoires.");
      process.exit(1);
    }
    if (mdp1 !== mdp2) {
      console.error("Les deux mots de passe ne correspondent pas.");
      process.exit(1);
    }
    if (mdp1.length < 10) {
      console.error("Le mot de passe doit faire au moins 10 caractères.");
      process.exit(1);
    }

    const existant = await pool.query("SELECT id FROM users WHERE email = $1", [email]);
    if (existant.rowCount > 0) {
      console.error("Un compte existe déjà avec cet email.");
      process.exit(1);
    }

    const hash = await argon2.hash(mdp1, { type: argon2.argon2id });
    await pool.query(
      "INSERT INTO users (email, password_hash, nom, service, role) VALUES ($1, $2, $3, $4, 'admin')",
      [email, hash, nom, service]
    );
    console.log(`Administrateur ${nom} <${email}> créé avec succès.`);
  } finally {
    rl.close();
    await pool.end();
  }
}

/* ------------------------------------------------------------------ */
/* Application Express                                                 */
/* ------------------------------------------------------------------ */

const app = express();
app.disable("x-powered-by");
if (TRUST_PROXY) app.set("trust proxy", 1);
app.use(express.json({ limit: "100kb" }));

const PgSessionStore = ConnectPgSimple(session);
app.use(
  session({
    store: new PgSessionStore({ pool, tableName: "session" }),
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: COOKIE_SECURE,
      maxAge: 8 * 60 * 60 * 1000, // session de 8 heures
    },
  })
);

/* Rattache l'utilisateur connecté (le cas échéant) à chaque requête. */
app.use(async (req, res, next) => {
  if (req.session && req.session.userId) {
    try {
      const { rows } = await pool.query("SELECT * FROM users WHERE id = $1", [
        req.session.userId,
      ]);
      req.user = rows[0] || null;
    } catch (e) {
      req.user = null;
    }
  }
  next();
});

const publicUser = (u) => ({
  id: u.id,
  email: u.email,
  nom: u.nom,
  service: u.service,
  role: u.role,
});

function requireAuth(req, res, next) {
  if (!req.user) return res.status(401).json({ error: "Authentification requise." });
  next();
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: "Authentification requise." });
    if (!roles.includes(req.user.role))
      return res.status(403).json({ error: "Droits insuffisants pour cette action." });
    next();
  };
}

/* Enveloppe async pour la gestion d'erreurs */
const h = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

/* ------------------------------------------------------------------ */
/* Anti-force brute sur la connexion (5 échecs / IP / 15 min,          */
/* en mémoire : remis à zéro au redémarrage, non partagé entre         */
/* plusieurs instances du serveur).                                    */
/* ------------------------------------------------------------------ */

const LOGIN_ECHECS = new Map();
const LOGIN_MAX_ECHECS = 5;
const LOGIN_FENETRE_MS = 15 * 60 * 1000;

function ipBloquee(ip) {
  const e = LOGIN_ECHECS.get(ip);
  return !!e && Date.now() <= e.resetAt && e.echecs >= LOGIN_MAX_ECHECS;
}

function enregistrerEchec(ip) {
  const e = LOGIN_ECHECS.get(ip);
  if (!e || Date.now() > e.resetAt) {
    LOGIN_ECHECS.set(ip, { echecs: 1, resetAt: Date.now() + LOGIN_FENETRE_MS });
  } else {
    e.echecs += 1;
  }
}

/* ------------------------------------------------------------------ */
/* Authentification                                                    */
/* ------------------------------------------------------------------ */

app.post(
  "/api/login",
  h(async (req, res) => {
    const email = String((req.body || {}).email || "").trim().toLowerCase();
    const password = String((req.body || {}).password || "");
    if (!email || !password)
      return res.status(400).json({ error: "Email et mot de passe requis." });

    if (ipBloquee(req.ip))
      return res
        .status(429)
        .json({ error: "Trop de tentatives de connexion. Réessayez dans un quart d'heure." });

    const { rows } = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    const u = rows[0];
    const hashValide = u ? await argon2.verify(u.password_hash, password).catch(() => false) : false;
    if (!u || !hashValide) {
      enregistrerEchec(req.ip);
      return res.status(401).json({ error: "Identifiants invalides." });
    }

    LOGIN_ECHECS.delete(req.ip);

    /* Régénère l'identifiant de session PUIS y écrit l'utilisateur :
       dans l'autre sens, regenerate() remplaçait la session par une
       session vide et la connexion était perdue (anti-fixation). */
    req.session.regenerate(() => {
      req.session.userId = u.id;
      res.json({ user: publicUser(u) });
    });
  })
);

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get("/api/me", requireAuth, (req, res) => {
  res.json({ user: publicUser(req.user) });
});

/* ------------------------------------------------------------------ */
/* Interventions                                                       */
/* ------------------------------------------------------------------ */

/* Champs VARCHAR(255) côté PostgreSQL : on borne la saisie pour
   renvoyer un 400 explicite au lieu d'une erreur 500. */
function validerIntervention(b) {
  const erreurs = [];
  const date = String(b.date || "");
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date) || Number.isNaN(Date.parse(date)))
    erreurs.push("La date est obligatoire (format AAAA-MM-JJ).");
  if (!String(b.batiment || "").trim())
    erreurs.push("Le bâtiment / espace est obligatoire.");
  else if (String(b.batiment).trim().length > MAX_VARCHAR)
    erreurs.push("Le bâtiment / espace est trop long (255 caractères max).");
  if (!String(b.type || "").trim())
    erreurs.push("Le type d'intervention est obligatoire.");
  else if (String(b.type).trim().length > MAX_VARCHAR)
    erreurs.push("Le type d'intervention est trop long (255 caractères max).");
  return erreurs;
}

function champsIntervention(b) {
  return [
    b.date,
    String(b.batiment).trim().slice(0, MAX_VARCHAR),
    String(b.type).trim().slice(0, MAX_VARCHAR),
    String(b.horaires || "").trim().slice(0, MAX_VARCHAR),
    String(b.hote || "").trim().slice(0, MAX_VARCHAR),
    Boolean(b.proxyclick),
    Boolean(b.visite_prevention),
    Boolean(b.plan_prevention),
    Boolean(b.registre_securite),
    Boolean(b.protocole_prevenance),
    String(b.observations || ""),
  ];
}

const COLONNES_INTERVENTION = `id, to_char(date, 'YYYY-MM-DD') AS date, batiment, type,
       horaires, hote, proxyclick, visite_prevention, plan_prevention,
       registre_securite, protocole_prevenance, observations, cree_par`;

const idValide = (v) => Number.isInteger(Number(v)) && Number(v) > 0;

app.get(
  "/api/interventions",
  requireAuth,
  h(async (req, res) => {
    const { from, to } = req.query;
    const conditions = [];
    const params = [];
    if (from && /^\d{4}-\d{2}-\d{2}$/.test(from)) {
      params.push(from);
      conditions.push(`date >= $${params.length}`);
    }
    if (to && /^\d{4}-\d{2}-\d{2}$/.test(to)) {
      params.push(to);
      conditions.push(`date <= $${params.length}`);
    }
    const where = conditions.length ? `WHERE ${conditions.join(" AND ")}` : "";
    const { rows } = await pool.query(
      `SELECT i.id, to_char(i.date, 'YYYY-MM-DD') AS date, i.batiment, i.type,
              i.horaires, i.hote, i.proxyclick, i.visite_prevention, i.plan_prevention,
              i.registre_securite, i.protocole_prevenance, i.observations, i.cree_par,
              u.nom AS cree_par_nom
         FROM interventions i
         JOIN users u ON u.id = i.cree_par
         ${where}
        ORDER BY i.date, i.id`,
      params
    );
    res.json({ interventions: rows });
  })
);

app.post(
  "/api/interventions",
  requireRole("gestionnaire", "admin"),
  h(async (req, res) => {
    const b = req.body || {};
    const erreurs = validerIntervention(b);
    if (erreurs.length) return res.status(400).json({ error: erreurs.join(" ") });

    const { rows } = await pool.query(
      `INSERT INTO interventions
         (date, batiment, type, horaires, hote, proxyclick, visite_prevention,
          plan_prevention, registre_securite, protocole_prevenance, observations, cree_par)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
       RETURNING ${COLONNES_INTERVENTION}`,
      [...champsIntervention(b), req.user.id]
    );
    res.status(201).json({ intervention: rows[0] });
  })
);

app.put(
  "/api/interventions/:id",
  requireRole("gestionnaire", "admin"),
  h(async (req, res) => {
    if (!idValide(req.params.id))
      return res.status(404).json({ error: "Intervention introuvable." });
    const b = req.body || {};
    const erreurs = validerIntervention(b);
    if (erreurs.length) return res.status(400).json({ error: erreurs.join(" ") });

    const { rows } = await pool.query(
      `UPDATE interventions SET
         date = $1, batiment = $2, type = $3, horaires = $4, hote = $5,
         proxyclick = $6, visite_prevention = $7, plan_prevention = $8,
         registre_securite = $9, protocole_prevenance = $10, observations = $11,
         updated_at = now()
       WHERE id = $12
       RETURNING ${COLONNES_INTERVENTION}`,
      [...champsIntervention(b), Number(req.params.id)]
    );
    if (rows.length === 0) return res.status(404).json({ error: "Intervention introuvable." });
    res.json({ intervention: rows[0] });
  })
);

app.delete(
  "/api/interventions/:id",
  requireRole("admin"),
  h(async (req, res) => {
    if (!idValide(req.params.id))
      return res.status(404).json({ error: "Intervention introuvable." });
    const { rowCount } = await pool.query("DELETE FROM interventions WHERE id = $1", [
      Number(req.params.id),
    ]);
    if (rowCount === 0) return res.status(404).json({ error: "Intervention introuvable." });
    res.json({ ok: true });
  })
);

/* ------------------------------------------------------------------ */
/* Utilisateurs (administrateur uniquement)                            */
/* ------------------------------------------------------------------ */

app.get(
  "/api/users",
  requireRole("admin"),
  h(async (req, res) => {
    const { rows } = await pool.query(
      "SELECT id, email, nom, service, role, created_at FROM users ORDER BY nom"
    );
    res.json({ users: rows });
  })
);

app.post(
  "/api/users",
  requireRole("admin"),
  h(async (req, res) => {
    const b = req.body || {};
    const email = String(b.email || "").trim().toLowerCase();
    const nom = String(b.nom || "").trim();
    const service = String(b.service || "").trim() || "-";
    const role = String(b.role || "");
    const password = String(b.password || "");

    const erreurs = [];
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) erreurs.push("Email invalide.");
    if (!nom) erreurs.push("Le nom est obligatoire.");
    if (!ROLES.includes(role)) erreurs.push("Rôle invalide.");
    if (password.length < 10) erreurs.push("Le mot de passe doit faire au moins 10 caractères.");
    if (erreurs.length) return res.status(400).json({ error: erreurs.join(" ") });

    try {
      const hash = await argon2.hash(password, { type: argon2.argon2id });
      const { rows } = await pool.query(
        `INSERT INTO users (email, password_hash, nom, service, role)
         VALUES ($1, $2, $3, $4, $5)
         RETURNING id, email, nom, service, role`,
        [email, hash, nom, service, role]
      );
      res.status(201).json({ user: rows[0] });
    } catch (e) {
      /* 23505 = violation d'unicité : deux admins créent le même email
         au même moment (la vérification préalable peut être dépassée). */
      if (e.code === "23505")
        return res.status(400).json({ error: "Un compte existe déjà avec cet email." });
      throw e;
    }
  })
);

app.patch(
  "/api/users/:id/role",
  requireRole("admin"),
  h(async (req, res) => {
    const role = String((req.body || {}).role || "");
    if (!idValide(req.params.id))
      return res.status(404).json({ error: "Utilisateur introuvable." });
    const id = Number(req.params.id);
    if (!ROLES.includes(role)) return res.status(400).json({ error: "Rôle invalide." });
    if (id === req.user.id)
      return res.status(400).json({ error: "Vous ne pouvez pas modifier votre propre rôle." });

    const { rows } = await pool.query("SELECT role FROM users WHERE id = $1", [id]);
    if (rows.length === 0) return res.status(404).json({ error: "Utilisateur introuvable." });

    /* Interdire de retirer le dernier administrateur. */
    if (rows[0].role === "admin" && role !== "admin") {
      const { rows: admins } = await pool.query(
        "SELECT count(*)::int AS n FROM users WHERE role = 'admin'"
      );
      if (admins[0].n <= 1)
        return res.status(400).json({ error: "Impossible de retirer le dernier administrateur." });
    }

    const maj = await pool.query(
      "UPDATE users SET role = $1 WHERE id = $2 RETURNING id, email, nom, service, role",
      [role, id]
    );
    res.json({ user: maj.rows[0] });
  })
);

/* ------------------------------------------------------------------ */
/* Frontend statique                                                   */
/* ------------------------------------------------------------------ */

app.use(express.static(path.join(__dirname, "public")));
app.use((req, res, next) => {
  if (req.method === "GET" && !req.path.startsWith("/api/"))
    return res.sendFile(path.join(__dirname, "public", "index.html"));
  next();
});

/* Gestionnaire d'erreurs global */
app.use((err, req, res, next) => {
  console.error(err);
  if (res.headersSent) return next(err);
  res.status(500).json({ error: "Erreur interne du serveur." });
});

/* ------------------------------------------------------------------ */
/* Point d'entrée                                                      */
/* ------------------------------------------------------------------ */

(async () => {
  const commande = process.argv[2];
  try {
    if (commande === "migrate") {
      await migrer();
    } else if (commande === "create-admin") {
      await creerAdmin();
    } else {
      app.listen(PORT, () => {
        console.log(`C2RMF — Planification des interventions`);
        console.log(`Serveur démarré : http://localhost:${PORT}`);
      });
    }
  } catch (e) {
    console.error("Erreur :", e.message);
    process.exit(1);
  }
})();