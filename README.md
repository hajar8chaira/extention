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
  zap: true
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
