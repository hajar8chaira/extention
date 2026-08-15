# Laboratoire de sécurité local

Ce laboratoire utilise le code source officiel d’OWASP Juice Shop comme application volontairement vulnérable.

## Sécurité

L’application est publiée uniquement sur `127.0.0.1:3000`. Ne remplacez pas cette adresse par `0.0.0.0` et n’exposez pas le port sur Internet ou un réseau partagé.

## Démarrage

Depuis `C:\Users\hajar\Desktop\pfa-start` :

```powershell
docker compose -f docker-compose.security-lab.yml up -d
```

Puis ouvrir `http://localhost:3000`.

L’image officielle préconstruite exécute l’application. Le dépôt `test-application/juice-shop` conserve le code source correspondant pour les analyses de Security Center.

## Arrêt

```powershell
docker compose -f docker-compose.security-lab.yml down
```

## Test avec Security Center

1. Lancer l’extension avec `F5`.
2. Dans l’Extension Development Host, ouvrir `test-application/juice-shop`.
3. Lancer `Security Center: Scan Workspace`.
4. Examiner les résultats Semgrep, Gitleaks, Trivy et ZAP.

ZAP exécute un baseline passif sur `http://127.0.0.1:3000`. Depuis son conteneur, l’extension convertit cette adresse en `host.docker.internal:3000`. Le MVP refuse toute cible non locale.
