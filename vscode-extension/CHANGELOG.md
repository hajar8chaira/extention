# Changelog

## Non publié

- SonarQube intégré comme scanner de première classe : modes `auto`, `local` et `docker`, preflight du serveur, attente bornée du traitement Compute Engine, récupération paginée des issues et des security hotspots, normalisation dans le modèle de finding commun.
- Jeton SonarQube conservé dans le SecretStorage de VS Code, transmis par variable d’environnement ou `--env-file` et masqué dans tous les messages.
- `docker-compose.sonarqube.yml` pour lancer SonarQube Community Build en local sur `127.0.0.1:9000`.

## 0.2.0

- ZAP local automatisé : détection, démarrage protégé, scan actif/JWT et arrêt propre.
- Import OpenAPI local par URL localhost ou fichier du workspace.
- Politique ZAP différenciée par sévérité.
- Replay contrôlé GET/HEAD/POST/PUT/PATCH, avec autorisation unique par session et audit automatique des écritures.
- Liaison d’une preuve HTTP à une vulnérabilité corrigée.
- Corrections natives Semgrep avec contrôle d’obsolescence, aperçu diff et re-scan ciblé.
- Notifications Slack et tickets Jira optionnels pour les findings confirmés, avec secrets dans VS Code SecretStorage.
- Fournisseur Ollama local : contexte minimal redacté, réponse structurée, validation unified diff, aperçu, application, re-scan et rollback.
- Dashboard, comparaisons, tendances, SARIF agrégé, CLI headless et CI incrémentale.
- SBOM, conformité des licences, scan historique Gitleaks et hook pre-commit.

## 0.1.0

- Première version du Security Center multi-scanners.
# Correction IA locale renforcée

- contexte ciblé avec imports, types et fonction liée au finding ;
- sortie Ollama structurée avec raison de sécurité, hypothèses et confiance ;
- confiance indépendante calculée par Security Center ;
- validation après patch par re-scan et script de tests déclaré, avec rollback proposé en cas d’échec.
