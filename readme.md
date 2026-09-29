C2RMF — Planification hebdomadaire des interventions

Application web de gestion de la planification des interventions du C2RMF.
Trois niveaux de profils : Administrateur, Gestionnaire (saisie des interventions), Visiteur (lecture seule).

Structure du projet

c2rmf-planning/
├── server.js          # Serveur Express : API REST, sessions, rôles
├── package.json       # Dépendances et scripts npm
├── README.md          # Ce fichier
└── public/
    └── index.html     # Interface web (SPA, sans build)

Prérequis





Node.js 18 ou plus récent (node -v pour vérifier)



PostgreSQL 14 ou plus récent, accessible en local ou sur le réseau



⚠️ La dépendance argon2 compile un module natif : npm install a besoin d'un compilateur (build-essential / Xcode Command Line Tools) sur le serveur.

Installation pas à pas

1. Créer la base de données

CREATE DATABASE c2rmf_planning;

Créez ensuite (optionnel mais recommandé) un utilisateur dédié :

CREATE USER c2rmf_app WITH PASSWORD 'mot_de_passe_solide';
GRANT ALL PRIVILEGES ON DATABASE c2rmf_planning TO c2rmf_app;

2. Récupérer les fichiers du projet

Placez dans le dossier c2rmf-planning/ les fichiers téléchargés depuis les canvases Vibe, renommés comme suit :







Canvas d'origine



Fichier dans le projet





c2rmf-planning — server.js



server.js





c2rmf-planning — index.html



public/index.html





c2rmf-planning — package.json



package.json





c2rmf-planning — README.md



README.md

3. Configurer les variables d'environnement

export DATABASE_URL="postgres://c2rmf_app:mot_de_passe_solide@localhost:5432/c2rmf_planning"
export SESSION_SECRET="$(openssl rand -hex 32)"   # chaîne aléatoire longue
export PORT=3000                                   # optionnel, 3000 par défaut

Si le site est servi derrière HTTPS (recommandé en production) :

export COOKIE_SECURE=true

Ces variables peuvent aussi être définies dans un fichier .env chargé par votre gestionnaire de processus (PM2, systemd).

4. Installer les dépendances

npm install

5. Créer les tables

npm run migrate

(commande équivalente : node server.js migrate)

6. Créer le premier administrateur

npm run create-admin

Le script demande interactivement le nom d'utilisateur, le nom complet et le mot de passe (haché avec Argon2id).

7. Démarrer le serveur

npm start

Le site est accessible sur : http://votre-serveur:3000

Après le premier démarrage





Connectez-vous avec le compte administrateur créé à l'étape 6.



Onglet Utilisateurs : créez les comptes gestionnaires et visiteurs.





Visiteur : consulte le planning et le tableau, exporte en CSV — aucune saisie.



Gestionnaire : crée et modifie les interventions.



Administrateur : tout + gestion des utilisateurs et suppression.



Le planning fonctionne par semaine : flèches ← → pour naviguer, bouton « Nouvelle intervention » (gestionnaire/admin) pour saisir une ligne (date, bâtiment/espace, type, horaires, hôte, cases cochées).

Notes de production





Processus : gardez le serveur actif avec PM2 ou systemd, ex. pm2 start server.js --name c2rmf-planning.



Reverse proxy : en production, servez l'application derrière nginx avec HTTPS (certificat interne ou Let's Encrypt), et définissez COOKIE_SECURE=true.



Accès réseau : pour un usage interne uniquement, restreignez l'accès au port 3000 au réseau local (pare-feu ou écoute sur IP interne).



Sauvegardes : sauvegardez régulièrement la base c2rmf_planning (pg_dump).



Sécurité : le serveur n'inclut pas de limitation de débit sur la connexion ; ajoutez-en une (ex. express-rate-limit) si le site est exposé sur Internet.

