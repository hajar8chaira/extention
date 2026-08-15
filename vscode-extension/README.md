# Security Center for VS Code

MVP du PFA : lancer Semgrep, Gitleaks, Trivy, OSV-Scanner et OWASP ZAP depuis VS Code, puis afficher les vulnérabilités, secrets potentiels, dépendances vulnérables, mauvaises configurations et alertes dynamiques directement dans l’onglet **Problems** et dans la vue **Security Center**.

Le guide utilisateur `GUIDE_UTILISATEUR.md`, inclus dans l’extension, décrit l’installation, la configuration Docker et le dépannage.

## Démarrage développeur

1. Ouvrir ce dossier dans VS Code.
2. Appuyer sur `F5` pour ouvrir un Extension Development Host.
3. Dans la nouvelle fenêtre, ouvrir un projet à analyser.
4. Exécuter `Security Center: Scan Workspace` depuis la palette de commandes.

Par défaut, l’extension exécute `semgrep`, `gitleaks`, `trivy`, `osv-scanner` et un baseline passif `ZAP` dans des conteneurs Docker temporaires. Docker Desktop doit être démarré et afficher **Engine running**. L’extension vérifie automatiquement le moteur avant chaque analyse.

Après normalisation et déduplication, Security Center réalise une corrélation prudente :

- confiance élevée : outils différents, même fichier, lignes proches et CWE commun ;
- confiance moyenne : CWE commun entre le code et ZAP, en attente du mapping endpoint-code.

Le dashboard sépare ces deux niveaux afin qu’une simple correspondance CWE ne soit pas présentée comme une vulnérabilité dynamiquement confirmée.

Chaque finding peut également être trié comme nouveau, confirmé, faux positif, risque accepté ou corrigé. Le dashboard conserve l’historique des statuts tout en calculant le risque actif sans les faux positifs et les résultats corrigés.

Le socle HTTP permet d’importer une capture HAR locale, de normaliser les requêtes/réponses, de masquer les en-têtes sensibles, puis de rejouer de façon contrôlée les requêtes `GET` et `HEAD`. Ce modèle sera partagé avec le connecteur Burp Montoya, les tests IDOR/JWT et la validation automatique des corrections.

## Commandes

- `Security Center: Scan Workspace`
- `Security Center: Clear Findings`

## Configuration

- `securityCenter.semgrep.command` : `auto`, `local` ou `docker`
- `securityCenter.semgrep.config` : configuration Semgrep, `p/security-audit` par défaut
- `securityCenter.gitleaks.enabled` : active ou désactive Gitleaks
- `securityCenter.gitleaks.command` : `auto`, `local` ou `docker`
- `securityCenter.trivy.enabled` : active ou désactive Trivy
- `securityCenter.trivy.command` : `auto`, `local` ou `docker`
- `securityCenter.trivy.image` : image Docker optionnelle à analyser
- `securityCenter.osv.enabled` : active ou désactive OSV-Scanner
- `securityCenter.zap.enabled` : active ou désactive ZAP
- `securityCenter.zap.targetUrl` : cible locale autorisée, `http://127.0.0.1:3000` par défaut
- `securityCenter.scan.timeoutSeconds` : timeout du scan

## Tests

```powershell
npm test
npm run check
```

## Capacités avancées

Le CLI partage les adaptateurs, normaliseurs, exclusions, corrélations et règles de politique avec l'extension :

```powershell
npm run scan:headless -- --workspace .. --tools Semgrep,Gitleaks,Trivy,OSV-Scanner --fail-on HIGH --format sarif --output ../security-center.sarif
```

Il retourne `1` lorsque la politique bloque la livraison et `2` lorsqu'un scanner échoue. Le workflow fourni publie le rapport avec `github/codeql-action/upload-sarif@v4`.

Le fichier versionné `security-center.yml` configure le scan historique Gitleaks, les règles métier Semgrep/Gitleaks, les exclusions natives par outil, une concurrence contrôlée (1 à 4 scanners) et les modes ZAP passif/actif/OpenAPI. `zap.mode: auto` privilégie ZAP installé localement, `local` l’impose et `docker` conserve explicitement l’ancien moteur. Le scan actif reste local et exige une confirmation explicite. L’authentification JWT utilise `zap.auth_login` et des identifiants fournis par variables d’environnement ou par les champs sécurisés de VS Code ; aucun mot de passe ou jeton n’est conservé dans les rapports. OSV active l'analyse d'appels pour Rust lorsqu'un `Cargo.lock` est détecté ; cette analyse n'est pas annoncée comme disponible pour JavaScript/TypeScript.

En mode local, `zap.openapi` accepte soit une URL servie par `localhost`, soit un fichier OpenAPI relatif au workspace. L’adaptateur importe le contrat avec l’API REST ZAP, lance le scan actif, attend réellement sa fin, récupère les alertes puis arrête le daemon. Exemple : `openapi: security/openapi-smoke.json`. Les URL distantes et les fichiers situés hors du workspace sont refusés.

`zap.policy_min_severity: HIGH` garde les alertes ZAP LOW/MEDIUM visibles dans le dashboard sans les compter dans `policy.max_active`. Les alertes ZAP HIGH/CRITICAL restent bloquantes. La valeur par défaut `INFO` conserve le comportement historique pour les projets qui ne configurent pas ce seuil.

L'autofix et les corrections générées par IA restent volontairement hors de cette phase.
