<?php
declare(strict_types=1);

/**
 * C2RMF — Planification des interventions
 * Serveur applicatif PHP : API REST + sessions + rôles + frontend statique.
 *
 * Réécriture en PHP (sans Node.js ni npm) de server.js — l'API et les
 * réponses JSON sont strictement identiques, le fichier public/index.html
 * fonctionne donc sans aucune modification.
 *
 * Prérequis : PHP 8.0+ avec l'extension pdo_pgsql (Argon2id natif si PHP est
 * compilé avec libargon2, sinon repli automatique sur bcrypt — les hachages
 * Argon2 produits par l'autre version restent vérifiables dans les deux sens).
 *
 * Commandes :
 *   php index.php migrate               -> crée / met à jour les tables PostgreSQL
 *   php index.php create-admin          -> crée interactivement le premier administrateur
 *   php -S 0.0.0.0:3000 index.php       -> démarre le serveur HTTP (développement / usage interne)
 *
 * En production : Apache ou nginx + PHP-FPM, avec toutes les requêtes non
 * statiques routées vers index.php (voir README).
 *
 * Variables d'environnement :
 *   DATABASE_URL   (requis)  ex. postgres://user:pass@localhost:5432/c2rmf_planning
 *   COOKIE_SECURE  mettre à true si le site est servi derrière HTTPS
 *
 * NB : SESSION_SECRET n'est pas nécessaire ici, PHP gère les sessions
 * nativement (sessions serveur, cookie HttpOnly SameSite=Lax).
 */

/* ------------------------------------------------------------------ */
/* Constantes                                                          */
/* ------------------------------------------------------------------ */

const ROLES = ['admin', 'gestionnaire', 'visiteur'];
const MESURES = [
    'proxyclick',
    'visite_prevention',
    'plan_prevention',
    'registre_securite',
    'protocole_prevenance',
];

function env(string $nom, ?string $defaut = null): ?string
{
    $v = getenv($nom);
    return ($v === false || $v === '') ? $defaut : $v;
}

function schemaSql(): string
{
    return <<<'SQL'
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
SQL;
}

/* ------------------------------------------------------------------ */
/* Sorties JSON                                                        */
/* ------------------------------------------------------------------ */

function jsonSortir(array $donnees, int $code = 200): void
{
    http_response_code($code);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($donnees, JSON_UNESCAPED_UNICODE);
    exit;
}

function erreurJson(int $code, string $message): void
{
    jsonSortir(['error' => $message], $code);
}

/* ------------------------------------------------------------------ */
/* Connexion PostgreSQL                                                */
/* ------------------------------------------------------------------ */

function connecter(): PDO
{
    $url = env('DATABASE_URL');
    if (!$url) {
        $msg = "Erreur : la variable d'environnement DATABASE_URL est requise.";
        if (PHP_SAPI === 'cli') {
            fwrite(STDERR, $msg . "\n");
            exit(1);
        }
        erreurJson(500, $msg);
    }

    $p = parse_url($url);
    $base = isset($p['path']) ? ltrim($p['path'], '/') : '';
    if (!$p || empty($p['host']) || $base === '') {
        $msg = 'Erreur : DATABASE_URL invalide (attendu : postgres://user:pass@hote:5432/base).';
        if (PHP_SAPI === 'cli') {
            fwrite(STDERR, $msg . "\n");
            exit(1);
        }
        erreurJson(500, $msg);
    }

    $dsn = sprintf('pgsql:host=%s;port=%d;dbname=%s', $p['host'], $p['port'] ?? 5432, $base);

    try {
        return new PDO($dsn, rawurldecode($p['user'] ?? ''), rawurldecode($p['pass'] ?? ''), [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES  => false,
        ]);
    } catch (PDOException $e) {
        $msg = 'Erreur de connexion à PostgreSQL : ' . $e->getMessage();
        if (PHP_SAPI === 'cli') {
            fwrite(STDERR, $msg . "\n");
            exit(1);
        }
        erreurJson(500, 'Erreur interne du serveur.');
    }
}

/* ------------------------------------------------------------------ */
/* Normalisation des lignes SQL -> JSON                                */
/* ------------------------------------------------------------------ */

/* PDO/pgsql peut renvoyer les booléens sous forme 't'/'f' ou true/false
   selon la version : on convertit explicitement pour un JSON identique
   à celui de server.js. */
function enBool($v): bool
{
    if (is_bool($v)) return $v;
    if (is_int($v))  return $v === 1;
    $s = strtolower((string) $v);
    return $s === 't' || $s === 'true' || $s === '1';
}

function normaliserIntervention(array $r): array
{
    $r['id'] = (int) $r['id'];
    $r['cree_par'] = (int) $r['cree_par'];
    foreach (MESURES as $m) {
        $r[$m] = enBool($r[$m] ?? false);
    }
    return $r;
}

function publicUser(array $u): array
{
    return [
        'id'      => (int) $u['id'],
        'email'   => $u['email'],
        'nom'     => $u['nom'],
        'service' => $u['service'],
        'role'    => $u['role'],
    ];
}

/* Hachage Argon2id si disponible, sinon bcrypt (les deux restent
   vérifiables par password_verify, y compris avec les hachages
   $argon2id$ produits par la version Node.js). */
function hacherMotDePasse(string $mdp): string
{
    $algo = defined('PASSWORD_ARGON2ID') ? PASSWORD_ARGON2ID : PASSWORD_BCRYPT;
    return password_hash($mdp, $algo);
}

/* ------------------------------------------------------------------ */
/* CLI : migration et création du premier administrateur                */
/* ------------------------------------------------------------------ */

function migrer(PDO $pdo): void
{
    $pdo->exec(schemaSql());
    echo "Base de données initialisée / à jour (users, interventions).\n";
}

function demander(string $texte): string
{
    echo $texte;
    return trim((string) fgets(STDIN));
}

function creerAdmin(PDO $pdo): void
{
    echo "--- Création du compte administrateur ---\n";
    $email   = strtolower(demander('Email : '));
    $nom     = demander('Nom complet : ');
    $service = demander('Service (optionnel) : ') ?: '-';
    $mdp1    = demander('Mot de passe : ');
    $mdp2    = demander('Confirmation du mot de passe : ');

    if ($email === '' || $nom === '' || $mdp1 === '') {
        fwrite(STDERR, "Email, nom et mot de passe sont obligatoires.\n");
        exit(1);
    }
    if ($mdp1 !== $mdp2) {
        fwrite(STDERR, "Les deux mots de passe ne correspondent pas.\n");
        exit(1);
    }
    if (strlen($mdp1) < 10) {
        fwrite(STDERR, "Le mot de passe doit faire au moins 10 caractères.\n");
        exit(1);
    }

    $st = $pdo->prepare('SELECT id FROM users WHERE email = ?');
    $st->execute([$email]);
    if ($st->fetch()) {
        fwrite(STDERR, "Un compte existe déjà avec cet email.\n");
        exit(1);
    }

    $st = $pdo->prepare(
        "INSERT INTO users (email, password_hash, nom, service, role) VALUES (?, ?, ?, ?, 'admin')"
    );
    $st->execute([$email, hacherMotDePasse($mdp1), $nom, $service]);
    echo "Administrateur $nom <$email> créé avec succès.\n";
}

/* ------------------------------------------------------------------ */
/* Mode CLI                                                            */
/* ------------------------------------------------------------------ */

if (PHP_SAPI === 'cli') {
    $commande = $argv[1] ?? '';
    try {
        $pdo = connecter();
        if ($commande === 'migrate') {
            migrer($pdo);
        } elseif ($commande === 'create-admin') {
            creerAdmin($pdo);
        } else {
            fwrite(STDERR, "Usage : php index.php [migrate|create-admin]\n");
            fwrite(STDERR, "Serveur HTTP : php -S 0.0.0.0:3000 index.php\n");
            exit(1);
        }
    } catch (Throwable $e) {
        fwrite(STDERR, 'Erreur : ' . $e->getMessage() . "\n");
        exit(1);
    }
    exit(0);
}

/* ------------------------------------------------------------------ */
/* Mode HTTP : sessions                                                */
/* ------------------------------------------------------------------ */

$COOKIE_SECURE = env('COOKIE_SECURE') === 'true';

ini_set('session.use_strict_mode', '1');
ini_set('session.gc_maxlifetime', (string) (8 * 3600)); // session de 8 heures

session_name('c2rmf_sess');
session_set_cookie_params([
    'httponly' => true,
    'samesite' => 'Lax',
    'secure'   => $COOKIE_SECURE,
    'lifetime' => 8 * 3600,
    'path'     => '/',
]);
session_start();

$pdo = connecter();

/* Rattache l'utilisateur connecté (le cas échéant) à chaque requête. */
$utilisateur = null;
if (!empty($_SESSION['user_id'])) {
    try {
        $st = $pdo->prepare('SELECT * FROM users WHERE id = ?');
        $st->execute([(int) $_SESSION['user_id']]);
        $utilisateur = $st->fetch() ?: null;
    } catch (Throwable $e) {
        $utilisateur = null;
    }
}

/* ------------------------------------------------------------------ */
/* Garde-fous d'authentification                                       */
/* ------------------------------------------------------------------ */

function exigerAuthentification(?array $u): array
{
    if ($u === null) {
        erreurJson(401, 'Authentification requise.');
    }
    return $u;
}

function exigerRole(?array $u, array $roles): array
{
    $u = exigerAuthentification($u);
    if (!in_array($u['role'], $roles, true)) {
        erreurJson(403, 'Droits insuffisants pour cette action.');
    }
    return $u;
}

/* Corps JSON de la requête (PUT/PATCH/DELETE inclus), limité à 100 ko. */
function corpsJson(): array
{
    $brut = file_get_contents('php://input', false, null, 0, 102400);
    if ($brut === false || $brut === '') {
        return [];
    }
    $d = json_decode($brut, true);
    return is_array($d) ? $d : [];
}

/* ------------------------------------------------------------------ */
/* Validation                                                           */
/* ------------------------------------------------------------------ */

function validerIntervention(array $b): array
{
    $erreurs = [];
    if (!preg_match('/^\d{4}-\d{2}-\d{2}$/', (string) ($b['date'] ?? ''))) {
        $erreurs[] = 'La date est obligatoire (format AAAA-MM-JJ).';
    }
    if (trim((string) ($b['batiment'] ?? '')) === '') {
        $erreurs[] = "Le bâtiment / espace est obligatoire.";
    }
    if (trim((string) ($b['type'] ?? '')) === '') {
        $erreurs[] = "Le type d'intervention est obligatoire.";
    }
    return $erreurs;
}

/* ------------------------------------------------------------------ */
/* Authentification                                                    */
/* ------------------------------------------------------------------ */

function routeLogin(PDO $pdo, array $b): void
{
    $email    = strtolower(trim((string) ($b['email'] ?? '')));
    $password = (string) ($b['password'] ?? '');
    if ($email === '' || $password === '') {
        erreurJson(400, 'Email et mot de passe requis.');
    }

    $st = $pdo->prepare('SELECT * FROM users WHERE email = ?');
    $st->execute([$email]);
    $u = $st->fetch();

    $hashValide = $u ? password_verify($password, $u['password_hash']) : false;
    if (!$u || !$hashValide) {
        erreurJson(401, 'Identifiants invalides.');
    }

    /* Régénération de l'identifiant de session (anti-fixation). */
    session_regenerate_id(true);
    $_SESSION['user_id'] = (int) $u['id'];

    jsonSortir(['user' => publicUser($u)]);
}

function routeLogout(): void
{
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $p = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000, $p['path'], $p['domain'] ?? '', $p['secure'], $p['httponly']);
    }
    session_destroy();
    jsonSortir(['ok' => true]);
}

/* ------------------------------------------------------------------ */
/* Interventions                                                       */
/* ------------------------------------------------------------------ */

function routeListerInterventions(PDO $pdo, array $u): void
{
    exigerAuthentification($u);

    $conditions = [];
    $params = [];

    $from = (string) ($_GET['from'] ?? '');
    if ($from !== '' && preg_match('/^\d{4}-\d{2}-\d{2}$/', $from)) {
        $params[] = $from;
        $conditions[] = 'i.date >= ?';
    }
    $to = (string) ($_GET['to'] ?? '');
    if ($to !== '' && preg_match('/^\d{4}-\d{2}-\d{2}$/', $to)) {
        $params[] = $to;
        $conditions[] = 'i.date <= ?';
    }
    $where = $conditions ? 'WHERE ' . implode(' AND ', $conditions) : '';

    $sql = "SELECT i.id, to_char(i.date, 'YYYY-MM-DD') AS date, i.batiment, i.type,
                   i.horaires, i.hote, i.proxyclick, i.visite_prevention, i.plan_prevention,
                   i.registre_securite, i.protocole_prevenance, i.observations, i.cree_par,
                   u.nom AS cree_par_nom
              FROM interventions i
              JOIN users u ON u.id = i.cree_par
              $where
             ORDER BY i.date, i.id";
    $st = $pdo->prepare($sql);
    $st->execute($params);

    jsonSortir(['interventions' => array_map('normaliserIntervention', $st->fetchAll())]);
}

function routeCreerIntervention(PDO $pdo, array $u, array $b): void
{
    $u = exigerRole($u, ['gestionnaire', 'admin']);

    $erreurs = validerIntervention($b);
    if ($erreurs) {
        erreurJson(400, implode(' ', $erreurs));
    }

    $sql = 'INSERT INTO interventions
              (date, batiment, type, horaires, hote, proxyclick, visite_prevention,
               plan_prevention, registre_securite, protocole_prevenance, observations, cree_par)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
            RETURNING id, to_char(date, \'YYYY-MM-DD\') AS date, batiment, type, horaires, hote,
                      proxyclick, visite_prevention, plan_prevention, registre_securite,
                      protocole_prevenance, observations, cree_par';
    $st = $pdo->prepare($sql);
    $st->execute([
        $b['date'],
        trim((string) $b['batiment']),
        trim((string) $b['type']),
        trim((string) ($b['horaires'] ?? '')),
        trim((string) ($b['hote'] ?? '')),
        !empty($b['proxyclick']),
        !empty($b['visite_prevention']),
        !empty($b['plan_prevention']),
        !empty($b['registre_securite']),
        !empty($b['protocole_prevenance']),
        (string) ($b['observations'] ?? ''),
        (int) $u['id'],
    ]);

    jsonSortir(['intervention' => normaliserIntervention($st->fetch())], 201);
}

function routeModifierIntervention(PDO $pdo, array $u, int $id, array $b): void
{
    $u = exigerRole($u, ['gestionnaire', 'admin']);

    $erreurs = validerIntervention($b);
    if ($erreurs) {
        erreurJson(400, implode(' ', $erreurs));
    }

    $sql = 'UPDATE interventions SET
               date = ?, batiment = ?, type = ?, horaires = ?, hote = ?,
               proxyclick = ?, visite_prevention = ?, plan_prevention = ?,
               registre_securite = ?, protocole_prevenance = ?, observations = ?,
               updated_at = now()
             WHERE id = ?
            RETURNING id, to_char(date, \'YYYY-MM-DD\') AS date, batiment, type, horaires, hote,
                      proxyclick, visite_prevention, plan_prevention, registre_securite,
                      protocole_prevenance, observations, cree_par';
    $st = $pdo->prepare($sql);
    $st->execute([
        $b['date'],
        trim((string) $b['batiment']),
        trim((string) $b['type']),
        trim((string) ($b['horaires'] ?? '')),
        trim((string) ($b['hote'] ?? '')),
        !empty($b['proxyclick']),
        !empty($b['visite_prevention']),
        !empty($b['plan_prevention']),
        !empty($b['registre_securite']),
        !empty($b['protocole_prevenance']),
        (string) ($b['observations'] ?? ''),
        $id,
    ]);

    $ligne = $st->fetch();
    if (!$ligne) {
        erreurJson(404, 'Intervention introuvable.');
    }
    jsonSortir(['intervention' => normaliserIntervention($ligne)]);
}

function routeSupprimerIntervention(PDO $pdo, array $u, int $id): void
{
    exigerRole($u, ['admin']);

    $st = $pdo->prepare('DELETE FROM interventions WHERE id = ?');
    $st->execute([$id]);
    if ($st->rowCount() === 0) {
        erreurJson(404, 'Intervention introuvable.');
    }
    jsonSortir(['ok' => true]);
}

/* ------------------------------------------------------------------ */
/* Utilisateurs (administrateur uniquement)                            */
/* ------------------------------------------------------------------ */

function routeListerUtilisateurs(PDO $pdo, array $u): void
{
    exigerRole($u, ['admin']);

    $st = $pdo->query(
        "SELECT id, email, nom, service, role,
                to_char(created_at, 'YYYY-MM-DD\"T\"HH24:MI:SS') AS created_at
           FROM users ORDER BY nom"
    );
    $users = array_map(function (array $r): array {
        $r['id'] = (int) $r['id'];
        return $r;
    }, $st->fetchAll());

    jsonSortir(['users' => $users]);
}

function routeCreerUtilisateur(PDO $pdo, array $u, array $b): void
{
    exigerRole($u, ['admin']);

    $email    = strtolower(trim((string) ($b['email'] ?? '')));
    $nom      = trim((string) ($b['nom'] ?? ''));
    $service  = trim((string) ($b['service'] ?? '')) ?: '-';
    $role     = (string) ($b['role'] ?? '');
    $password = (string) ($b['password'] ?? '');

    $erreurs = [];
    if (!preg_match('/^[^\s@]+@[^\s@]+\.[^\s@]+$/', $email)) $erreurs[] = 'Email invalide.';
    if ($nom === '')                                       $erreurs[] = 'Le nom est obligatoire.';
    if (!in_array($role, ROLES, true))                     $erreurs[] = 'Rôle invalide.';
    if (strlen($password) < 10)                            $erreurs[] = 'Le mot de passe doit faire au moins 10 caractères.';
    if ($erreurs) {
        erreurJson(400, implode(' ', $erreurs));
    }

    $st = $pdo->prepare('SELECT id FROM users WHERE email = ?');
    $st->execute([$email]);
    if ($st->fetch()) {
        erreurJson(400, 'Un compte existe déjà avec cet email.');
    }

    $st = $pdo->prepare(
        'INSERT INTO users (email, password_hash, nom, service, role)
         VALUES (?, ?, ?, ?, ?)
         RETURNING id, email, nom, service, role'
    );
    $st->execute([$email, hacherMotDePasse($password), $nom, $service, $role]);
    $nouveau = $st->fetch();
    $nouveau['id'] = (int) $nouveau['id'];

    jsonSortir(['user' => $nouveau], 201);
}

function routeModifierRoleUtilisateur(PDO $pdo, array $u, int $id, array $b): void
{
    $u = exigerRole($u, ['admin']);

    $role = (string) ($b['role'] ?? '');
    if (!in_array($role, ROLES, true)) {
        erreurJson(400, 'Rôle invalide.');
    }
    if ($id === (int) $u['id']) {
        erreurJson(400, 'Vous ne pouvez pas modifier votre propre rôle.');
    }

    $st = $pdo->prepare('SELECT role FROM users WHERE id = ?');
    $st->execute([$id]);
    $cible = $st->fetch();
    if (!$cible) {
        erreurJson(404, 'Utilisateur introuvable.');
    }

    /* Interdire de retirer le dernier administrateur. */
    if ($cible['role'] === 'admin' && $role !== 'admin') {
        $n = (int) $pdo->query("SELECT count(*) FROM users WHERE role = 'admin'")->fetchColumn();
        if ($n <= 1) {
            erreurJson(400, 'Impossible de retirer le dernier administrateur.');
        }
    }

    $st = $pdo->prepare(
        'UPDATE users SET role = ? WHERE id = ? RETURNING id, email, nom, service, role'
    );
    $st->execute([$role, $id]);
    $maj = $st->fetch();
    $maj['id'] = (int) $maj['id'];

    jsonSortir(['user' => $maj]);
}

/* ------------------------------------------------------------------ */
/* Frontend statique                                                   */
/* ------------------------------------------------------------------ */

function servirSpa(): void
{
    $fichier = __DIR__ . '/public/index.html';
    if (!is_readable($fichier)) {
        http_response_code(500);
        header('Content-Type: text/plain; charset=utf-8');
        echo 'Erreur : public/index.html est introuvable.';
        return;
    }
    header('Content-Type: text/html; charset=utf-8');
    readfile($fichier);
}

/* ------------------------------------------------------------------ */
/* Routeur                                                             */
/* ------------------------------------------------------------------ */

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$path    = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';

try {
    if ($path === '/api/login' && $method === 'POST') {
        routeLogin($pdo, corpsJson());

    } elseif ($path === '/api/logout' && $method === 'POST') {
        routeLogout();

    } elseif ($path === '/api/me' && $method === 'GET') {
        $u = exigerAuthentification($utilisateur);
        jsonSortir(['user' => publicUser($u)]);

    } elseif ($path === '/api/interventions' && $method === 'GET') {
        routeListerInterventions($pdo, $utilisateur);

    } elseif ($path === '/api/interventions' && $method === 'POST') {
        routeCreerIntervention($pdo, $utilisateur, corpsJson());

    } elseif (preg_match('#^/api/interventions/(\d+)$#', $path, $m)) {
        $id = (int) $m[1];
        if ($method === 'PUT') {
            routeModifierIntervention($pdo, $utilisateur, $id, corpsJson());
        } elseif ($method === 'DELETE') {
            routeSupprimerIntervention($pdo, $utilisateur, $id);
        } else {
            erreurJson(405, 'Méthode non autorisée.');
        }

    } elseif ($path === '/api/users' && $method === 'GET') {
        routeListerUtilisateurs($pdo, $utilisateur);

    } elseif ($path === '/api/users' && $method === 'POST') {
        routeCreerUtilisateur($pdo, $utilisateur, corpsJson());

    } elseif (preg_match('#^/api/users/(\d+)/role$#', $path, $m) && $method === 'PATCH') {
        routeModifierRoleUtilisateur($pdo, $utilisateur, (int) $m[1], corpsJson());

    } elseif (str_starts_with($path, '/api/')) {
        erreurJson(404, 'Route inconnue.');

    } elseif ($method === 'GET') {
        /* Toute autre page GET sert l'application (SPA). */
        servirSpa();

    } else {
        erreurJson(405, 'Méthode non autorisée.');
    }
} catch (PDOException $e) {
    error_log('C2RMF: ' . $e->getMessage());
    erreurJson(500, 'Erreur interne du serveur.');
} catch (Throwable $e) {
    error_log('C2RMF: ' . $e->getMessage());
    erreurJson(500, 'Erreur interne du serveur.');
}
