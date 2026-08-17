# Security Center

Extension DevSecOps/AppSec pour Visual Studio Code avec scanners Docker, backend local FastAPI, dashboard intégré et application vulnérable contrôlée.

## Structure

```text
pfa-start/
├── vscode-extension/          Extension VS Code et dashboard Webview
├── backend/                   API FastAPI et stockage SQLite
├── test-application/
│   └── juice-shop/            Code source OWASP Juice Shop
├── docker-compose.backend.yml
├── docker-compose.security-lab.yml
├── docker-compose.sonarqube.yml
├── PROJECT_SCOPE.md
└── SECURITY_LAB.md
```

## Backend

```powershell
docker compose -f docker-compose.backend.yml up -d --build
```

API :

- santé : `http://127.0.0.1:8765/health`
- documentation : `http://127.0.0.1:8765/docs`
- dashboard JSON : `http://127.0.0.1:8765/api/v1/dashboard`

Les données SQLite sont conservées dans le volume Docker `security-center-data`.

## Extension

1. Ouvrir `vscode-extension` dans VS Code.
2. Appuyer sur `F5`.
3. Dans l’Extension Development Host, ouvrir le projet à analyser.
4. Ouvrir l’icône Security Center.
5. Consulter le **Dashboard** ou lancer **Security Center: Scan Workspace**.

Le scan continue si le backend est arrêté. Dans ce cas, la Webview affiche `backend: offline` et les résultats restent disponibles dans la TreeView et Problems.

## Application vulnérable

```powershell
docker compose -f docker-compose.security-lab.yml up -d
```

Juice Shop est accessible uniquement sur `http://127.0.0.1:3000`.

## SonarQube

SonarQube est désactivé par défaut : il exige un serveur joignable et un jeton. Activez-le avec `securityCenter.sonar.enabled`.

**Serveur SonarQube Community Build local (développement)**

```powershell
docker compose -f docker-compose.sonarqube.yml up -d
```

Le serveur écoute sur `http://127.0.0.1:9000` et met une à deux minutes à démarrer. Connectez-vous avec le compte `admin` initial, changez le mot de passe imposé par SonarQube, puis créez un jeton dans **Mon compte > Sécurité**. Enregistrez-le avec **Security Center: Configurer le jeton SonarQube** : il est conservé dans le SecretStorage de VS Code et n’est jamais écrit dans `security-center.yml`, `settings.json`, `sonar-project.properties`, les journaux ni les rapports.

**Option A — SonarScanner CLI local**

Vérifiez l’installation avec `sonar-scanner --version`. **Security Center: Vérifier la configuration SonarQube** affiche l’état du serveur, la version du scanner détectée et la présence du jeton.

**Option B — SonarScanner via Docker**

Aucune installation locale n’est nécessaire : l’image `sonarsource/sonar-scanner-cli` est utilisée automatiquement lorsque le CLI local est absent. Le workspace est monté en lecture seule et le répertoire de travail du scanner reste hors du dépôt. Un serveur SonarQube reste requis dans les deux cas.

Le mode `securityCenter.sonar.mode` accepte `auto` (CLI local puis Docker), `local` ou `docker`, comme les autres scanners. `securityCenter.sonar.hostUrl` n’est lu que depuis les paramètres VS Code : un `security-center.yml` versionné ne peut pas rediriger l’analyse ni le jeton vers un autre serveur. En headless, le jeton provient uniquement de la variable d’environnement `SONAR_TOKEN`.

Si le dépôt contient déjà un `sonar-project.properties`, il fait autorité et n’est pas modifié. Sinon Security Center construit les propriétés minimales à la volée, sans créer de fichier dans le projet.

## Snyk

Snyk est désactivé par défaut : il exige un compte Snyk et un jeton. Activez-le avec `securityCenter.snyk.enabled` ou depuis la carte Snyk de **Configuration des scanners**.

Créez le jeton dans Snyk via **Account settings > Auth Token**, puis enregistrez-le avec **Security Center: Configurer le jeton Snyk**. Il est conservé dans le SecretStorage de VS Code et n’est jamais écrit dans `security-center.yml`, `settings.json`, les journaux, les findings ni les rapports. Il est transmis aux processus uniquement par la variable d’environnement `SNYK_TOKEN`, jamais dans la ligne de commande.

**Option A — CLI Snyk local**

Le bouton **Installer Snyk CLI** télécharge l’exécutable officiel depuis `downloads.snyk.io`, vérifie son empreinte SHA-256 publiée par Snyk et l’installe dans le stockage privé de l’extension, sans droit administrateur et sans modifier le PATH système. Un CLI Snyk déjà présent sur le PATH est réutilisé tel quel.

**Option B — Snyk via Docker**

L’image officielle `snyk/snyk:linux` est utilisée automatiquement lorsque le CLI local est absent. Le workspace est monté en lecture seule, sans privilège supplémentaire ni socket Docker, et le bootstrap de build de l’image (`npm install`, `mvn install`, `pip install`) est neutralisé pour qu’aucune commande de build ne soit exécutée dans le projet analysé.

Le mode `securityCenter.snyk.mode` accepte `auto` (CLI local puis Docker), `local` ou `docker`. Trois capacités sont disponibles :

| Capacité | Réglage | Catégorie Security Center | Disponibilité |
| --- | --- | --- | --- |
| Snyk Open Source | `securityCenter.snyk.includeOpenSource` (activé) | SCA / dépendances | tout compte Snyk |
| Snyk Code | `securityCenter.snyk.includeCode` | SAST | selon l’offre et l’activation de l’organisation |
| Snyk IaC | `securityCenter.snyk.includeIaC` | mauvaises configurations | selon l’offre |

Si Snyk Code ou Snyk IaC n’est pas disponible pour le compte, la capacité est signalée explicitement dans la carte Snyk et Snyk Open Source continue de s’exécuter normalement. En headless, le jeton provient uniquement de `SNYK_TOKEN` : `node src/cli.js scan --tools Snyk --snyk-mode auto`.

Les résultats Snyk Open Source désignent un manifeste et non une ligne de code : ils restent visibles dans Security Center avec le manifeste comme localisation, sans être épinglés à une fausse ligne dans le panneau Problems.

## Burp Suite et revalidation

Burp est optionnel. Dans le dashboard, **Installer / configurer Burp** détecte si Burp est installé ou démarré, propose le téléchargement Community officiel et affiche le connecteur Java inclus. La capture automatique accepte uniquement `localhost`, `127.0.0.1` et `::1`, masque les en-têtes sensibles et déduplique durablement les requêtes identiques.

La commande **Historique et exports** charge un ancien scan ou l’exporte en JSON/HTML. Le cycle de triage est : `new → triaged → probable → confirmed → fixed → validated`. Le statut `validated` doit être choisi uniquement après un nouveau scan où l’alerte corrigée a disparu. La comparaison HTTP GET/HEAD est une preuve fonctionnelle optionnelle ; elle ne prouve pas seule la correction d’une vulnérabilité.

## Arrêt

```powershell
docker compose -f docker-compose.backend.yml down
docker compose -f docker-compose.security-lab.yml down
```

## Historique, exports et validation réelle

- Historique : `GET /api/v1/scans`
- Détail : `GET /api/v1/scans/{id}`
- Exports : `GET /api/v1/scans/{id}/export.json` et `export.html`
- Le bouton d’annulation interrompt le scanner actif et conserve les résultats déjà obtenus.

Pour reproduire une analyse réelle complète :

```powershell
cd vscode-extension
npm run scan:real
```

Les rapports sont enregistrés dans `security-reports/`. La dernière exécution contrôlée est décrite dans `VALIDATION_REPORT.md`.

## Politique projet `security-center.yml`

Le bouton **Configurer la politique projet** crée un fichier versionnable avec des valeurs sûres. Exemple :

```yaml
version: 1
scanners:
  semgrep: true
  gitleaks: true
  trivy: true
  osv: true
  sonarqube: true
  zap: true
sonarqube:
  mode: auto
  include_code_smells: false
policy:
  fail_on: HIGH
  max_active: 0
  include_tests: false
licenses:
  denied: [AGPL-3.0, GPL-3.0]
gitleaks:
  history: false
  history_incremental: true
  config: ""
semgrep:
  custom_rules: ""
zap:
  mode: auto
  local_path: ""
  policy_min_severity: HIGH
  active: false
  openapi: ""
  context: ""
  user: ""
exclusions:
  global_files: [node_modules/**, dist/**]
  semgrep_files: []
  semgrep_rules: []
  trivy_files: []
  zap_routes: [/logout]
execution:
  max_parallel_scanners: 2
```

`gitleaks.history: true` active le scan de tout l’historique Git. Lors du premier passage, Gitleaks utilise `--log-opts=--all`. Si `history_incremental` est activé, les passages suivants examinent uniquement `dernier_SHA..HEAD`. Le SHA de référence n’est conservé qu’après un scan réussi. Chaque finding historique conserve le commit d’introduction fourni par Gitleaks, mais jamais la valeur du secret.

`gitleaks.config` accepte un chemin relatif au dépôt vers un fichier TOML de règles partagées. La configuration est transmise au scanner local ou traduite vers le chemin `/src/...` dans le conteneur Docker.

### Phase 2 : scanners approfondis

`semgrep.custom_rules` ajoute un fichier de règles métier versionné aux règles publiques. Les exemples de `security-rules/semgrep.yml` couvrent notamment `eval`, les secrets JWT, les redirections non validées et les commandes shell alimentées par une requête. `security-rules/gitleaks.toml` complète les règles standard avec deux formats fictifs de jetons internes.

Les exclusions globales s'ajoutent toujours aux exclusions spécifiques : une exclusion ne peut pas être réactivée par un scanner. Elles sont traduites vers `--exclude` Semgrep, `[allowlist].paths` Gitleaks et `--skip-files` Trivy. Les règles Semgrep utilisent `--exclude-rule`; les routes ZAP deviennent des entrées natives `OUTOFSCOPE`.

`execution.max_parallel_scanners` accepte 1 à 4 (2 par défaut). Semgrep, Gitleaks, Trivy et OSV peuvent s'exécuter ensemble dans cette limite. ZAP reste dans une phase séparée. Une annulation interrompt les processus actifs et empêche le démarrage des scanners encore en attente.

Le mode ZAP par défaut reste le baseline passif. `zap.active: true` sélectionne le full scan. `zap.openapi` sélectionne le scan API et accepte une URL locale ou un fichier relatif au workspace. Avec `zap.mode: auto`, Security Center privilégie ZAP local, démarre son daemon avec une clé API temporaire, orchestre import/crawl, scan actif, polling et récupération des alertes, puis l’arrête. Ces modes offensifs exigent une confirmation modale auditée ; un refus exécute le baseline. Les cibles externes et fichiers hors workspace sont refusés. L’authentification JWT est injectée uniquement en mémoire à partir des variables ou secrets VS Code configurés, sans stocker le jeton dans le YAML ou le rapport.

La reachability OSV est activée automatiquement avec `--call-analysis=rust` lorsqu'un `Cargo.lock` est détecté. OSV-Scanner ne documente pas actuellement cette analyse pour JavaScript/TypeScript : sur Juice Shop, le dashboard indique donc « Non évaluée pour cet écosystème ».

L'autofix et les corrections générées par IA restent volontairement différés.

## Protection pre-commit

Le bouton **Protéger les commits avec Gitleaks** installe un hook qui analyse les changements indexés avant chaque commit. Il utilise Gitleaks local puis Docker en secours. Un hook tiers existant n’est jamais écrasé automatiquement.

## SBOM, licences et tendances

- **Exporter le SBOM CycloneDX** produit un document CycloneDX JSON validé.
- **Contrôler les licences** applique d’abord `licenses.denied` du fichier projet, puis la configuration VS Code en secours.
- **Voir les tendances et le MTTR** analyse jusqu’à 100 scans sur 90 jours. Le MTTR reste « non calculable » tant qu’aucune séquence datée apparition → `fixed`/`validated` n’existe.

## Authentification optionnelle

Définir `SECURITY_CENTER_API_KEY` pour protéger `/api/v1/*`. La même clé doit être enregistrée via **Configurer la clé API** dans VS Code et saisie dans le champ masqué du connecteur Burp. La route `/health` reste publique. En développement local avec `F5`, laisser la variable vide conserve le fonctionnement sans authentification.

## Mode headless, SARIF et GitHub Actions

```powershell
node vscode-extension/src/cli.js scan `
  --workspace . `
  --tools Semgrep,Gitleaks,Trivy,OSV-Scanner `
  --semgrep-config security-rules/semgrep.yml `
  --fail-on HIGH `
  --format sarif `
  --output security-center.sarif
```

Codes de sortie : `0` conforme, `1` politique non respectée, `2` erreur de scanner ou de configuration. Un ZAP offensif headless exige `--zap-authorized`, `--actor` et `--justification`; cette preuve est incluse dans le rapport.

Le workflow [`.github/workflows/security-center.yml`](.github/workflows/security-center.yml) exécute les tests et les quatre scanners non dynamiques, applique le seuil `HIGH`, puis publie le SARIF dans GitHub Code Scanning. ZAP n'est pas lancé dans la CI par défaut, car une application locale et une autorisation explicite sont nécessaires.

Dans VS Code, une autorisation ZAP active/OpenAPI exige une justification et doit être enregistrée dans `audit_events` avant le démarrage. Si la persistance échoue, le scan offensif est refusé.
