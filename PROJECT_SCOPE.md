# Security Center — cadrage du projet

## Sujet

**Conception d’une extension DevSecOps/AppSec intelligente intégrée à Visual Studio Code pour orchestrer les analyses SAST, SCA et DAST, corréler les résultats, prioriser les vulnérabilités et valider les corrections.**

La contribution principale n’est pas un nouveau scanner. Security Center transforme les résultats de plusieurs outils en vulnérabilités unifiées, explicables et exploitables par le développeur.

## Principes

- L’extension VS Code est l’interface principale.
- Les scanners sont exécutés dans des conteneurs Docker reproductibles.
- Les résultats bruts sont toujours conservés.
- Une corrélation regroupe les résultats sans supprimer les preuves d’origine.
- Les scans actifs ciblent uniquement une application locale ou un environnement explicitement autorisé.
- Une correction proposée doit être approuvée par le développeur.
- Le machine learning sert à prioriser, pas à remplacer les scanners.

## Architecture cible

```text
Extension VS Code
        │
        ▼
Backend local FastAPI
        ├── Semgrep
        ├── Gitleaks
        ├── Trivy / OSV-Scanner
        └── OWASP ZAP
                │
                ▼
        Normalisation commune
                │
                ▼
        Corrélation SAST / DAST
                │
                ▼
        Priorisation explicable
                │
                ▼
        VS Code + validation
```

SQLite suffit pour le MVP. PostgreSQL, Jenkins, Grafana et les notifications sont différés.

## État actuel

### Réalisé

- Extension VS Code fonctionnelle en JavaScript.
- TreeView Security Center.
- Diagnostics dans l’onglet Problems.
- Navigation vers le fichier et la ligne.
- Semgrep avec Docker.
- Gitleaks avec Docker.
- Trivy avec Docker.
- Format de finding commun.
- Exécution séquentielle des scanners.
- Affichage de l’état de chaque scanner.
- Regroupement par outil, fichier et règle.
- Conservation des occurrences d’une règle regroupée.
- Guide utilisateur.
- Application OWASP Juice Shop avec code source.
- Laboratoire Docker local lié uniquement à `127.0.0.1`.

### À stabiliser

- Validation Docker de bout en bout depuis l’Extension Development Host.
- Journal d’exécution détaillé des scanners.
- Annulation d’un scan.
- Tests d’intégration avec de vrais rapports Semgrep, Gitleaks et Trivy.
- Distinction entre doublon visuel et faux positif confirmé.

## Version 1 — MVP indispensable

1. Stabiliser Semgrep, Gitleaks et Trivy.
2. Migrer progressivement l’orchestration vers FastAPI.
3. Ajouter SQLite pour les scans, findings et statuts.
4. Ajouter une Webview avec résumé et filtres.
5. Intégrer OWASP ZAP :
   - baseline scan ;
   - import OpenAPI ;
   - récupération JSON ;
   - preuves HTTP.
6. Définir un schéma normalisé inspiré de SARIF.
7. Réaliser une corrélation basique Semgrep–ZAP.
8. Ajouter les statuts :
   - New ;
   - Triaged ;
   - Probable ;
   - Confirmed ;
   - Fixed ;
   - Validated ;
   - False positive.
9. Exporter un rapport JSON et HTML.
10. Démontrer le parcours complet sur Juice Shop.

## Version 2 — valeur ajoutée

- Mapping endpoint vers contrôleur et ligne.
- Reachability hybride des dépendances et vulnérabilités.
- Capture et replay HTTP.
- Tests JWT, IDOR/BOLA, rôles et tenants.
- Validation automatique après correction.
- Jenkins et Quality Gates.
- Détection des régressions.
- Import complémentaire de résultats Burp.

## Version 3 — intelligence

- Score déterministe explicable.
- Dataset annoté à partir des résultats et décisions.
- Régression logistique comme baseline.
- Random Forest ou XGBoost si les données sont suffisantes.
- Probabilité d’exploitabilité et de faux positif.
- Explication des facteurs contribuant au score.
- Suggestions de correction avec validation humaine.
- Security Guard pour le code nouvellement inséré ou généré par IA.

## Axe de recherche — reachability hybride

La question étudiée est :

> Une alerte de dépendance ou de code est-elle réellement atteignable depuis une entrée applicative, et cette atteignabilité peut-elle être confirmée pendant un test DAST ?

L’analyse distingue quatre niveaux :

1. **Présente** : la version vulnérable existe dans le lockfile.
2. **Importée** : le package ou module est réellement importé par le projet.
3. **Statiquement atteignable** : un chemin existe dans le graphe d’appels depuis une route ou un point d’entrée vers la fonction concernée.
4. **Dynamiquement confirmée** : ZAP ou un replay HTTP exécute effectivement ce chemin.

```text
CVE dans Trivy/OSV
        ↓
Package importé ?
        ↓
Chemin route → contrôleur → appel ?
        ↓
Couverture observée pendant ZAP/replay ?
        ↓
Priorité et confiance augmentées
```

### Périmètre réaliste

Le prototype de reachability se limite d’abord à JavaScript/TypeScript :

- imports ES Modules et `require` ;
- routes Express ;
- appels inter-fichiers résolus par TypeScript ;
- dépendances directes ;
- instrumentation ou couverture pendant les requêtes DAST.

Les appels dynamiques, la réflexion, le chargement conditionnel et les dépendances transitives non résolues reçoivent le statut `potentially_reachable`, jamais `unreachable` par défaut.

Le MVP ne prétend pas reproduire l’analyse propriétaire de Snyk, Semgrep Supply Chain ou Endor Labs. Il évalue une méthode hybride limitée et mesurable sur l’application de démonstration.

### Données supplémentaires du finding

```json
{
  "reachability": "confirmed",
  "entrypoint": "POST /api/search",
  "call_path": [
    "routes/search.ts",
    "controllers/search.ts",
    "dependency.vulnerableFunction"
  ],
  "runtime_evidence": {
    "request_id": "replay-42",
    "executed": true
  }
}
```

### Mesures

- réduction du nombre d’alertes prioritaires ;
- précision des statuts reachable/unreachable ;
- faux négatifs dus aux appels dynamiques ;
- différence entre analyse statique et couverture dynamique ;
- temps et mémoire nécessaires à la construction du graphe ;
- nombre d’alertes confirmées par une route HTTP.

## Axe complémentaire — sécurité du code généré par IA

Le prototype ne prétend pas intercepter les suggestions internes d’une autre extension comme Copilot ou Cursor : l’API publique VS Code permet à une extension de fournir ses propres complétions, mais pas de lire librement les suggestions fantômes produites par les autres fournisseurs.

Security Center propose plutôt un **New Code Security Guard** :

1. observer les modifications du document ;
2. calculer le diff nouvellement inséré ;
3. lancer des règles rapides Semgrep/Gitleaks après acceptation ou enregistrement ;
4. afficher immédiatement un diagnostic ;
5. proposer d’annuler ou de corriger le changement ;
6. effectuer un scan complet avant commit.

Si Security Center fournit plus tard son propre fournisseur de suggestions IA, il pourra analyser ses propres propositions avant de les afficher. Pour du code produit par un outil tiers, l’origine IA ne peut pas toujours être prouvée ; le résultat doit être présenté comme analyse du **nouveau code**, pas comme détection certaine de code IA.

### Mesures

- délai entre insertion et alerte ;
- vulnérabilités détectées dans des échantillons générés par IA ;
- taux de faux positifs sur du code écrit manuellement ;
- comparaison scan du diff / scan complet ;
- nombre de vulnérabilités bloquées avant commit.

## Format normalisé minimal

```json
{
  "id": "stable-fingerprint",
  "tool": "semgrep",
  "scan_type": "sast",
  "rule_id": "rule.identifier",
  "category": "sql-injection",
  "cwe": ["CWE-89"],
  "severity": "high",
  "file": "src/controller.ts",
  "line": 51,
  "route": "/api/search",
  "method": "POST",
  "parameter": "query",
  "message": "Untrusted input reaches SQL query",
  "status": "new",
  "raw_finding_id": "source-result-id"
}
```

## Corrélation initiale

| Critère | Points |
|---|---:|
| CWE identique | 30 |
| Endpoint identique | 25 |
| Paramètre identique | 20 |
| Contrôleur identique | 15 |
| Méthode HTTP identique | 10 |

- `70–89` : corrélation probable.
- `90–100` : confirmation forte.
- Les résultats bruts restent consultables séparément.

## Démonstration de référence

```text
Semgrep détecte une injection dans le code
        +
ZAP confirme l’injection sur un endpoint
        ↓
Security Center associe les deux preuves
        ↓
Le développeur ouvre le contrôleur
        ↓
La correction est appliquée
        ↓
Semgrep et le test HTTP sont rejoués
        ↓
La vulnérabilité passe à Validated
```

## Critères d’évaluation

- Nombre de vulnérabilités connues détectées.
- Taux de faux positifs avant/après corrélation.
- Précision de la correspondance SAST–DAST.
- Temps d’analyse.
- Reproductibilité Docker.
- Temps nécessaire au développeur pour comprendre et localiser une alerte.
- Capacité à confirmer une correction par replay.
- Pour le ML : comparaison avec une priorisation basée uniquement sur la sévérité.

## Hors périmètre immédiat

- Grafana et Prometheus.
- Slack et e-mail.
- Déploiement cloud.
- PostgreSQL.
- Automatisation complète de Burp commercial.
- Réseau neuronal sans dataset suffisant.
