# Guide utilisateur — Security Center

## Prérequis

- Visual Studio Code 1.90 ou plus récent.
- Docker Desktop installé et démarré avec l’état **Engine running**.
- Une connexion Internet lors du premier téléchargement des images Docker.

## Installer le paquet VSIX

1. Ouvrir VS Code normalement, sans utiliser F5.
2. Ouvrir **Extensions** puis le menu `…`.
3. Choisir **Install from VSIX… / Installer à partir d’un fichier VSIX…**.
4. Sélectionner `security-center-vscode.vsix` (version interne `0.2.0`).
5. Recharger VS Code, ouvrir le projet puis sélectionner l’icône bouclier **Security Center**.

F5 reste le mode de développement : il ouvre une fenêtre **Extension Development Host** qui exécute directement le code source. Le VSIX sert uniquement à installer une version distribuable dans une fenêtre VS Code normale.

## Lancer une analyse

1. Ouvrir le projet à analyser dans VS Code.
2. Ouvrir la vue **Security Center** avec l’icône bouclier.
3. Cliquer sur l’icône d’analyse, ou lancer **Security Center: Scan Workspace** depuis la palette de commandes.
4. Attendre la fin des analyses Semgrep, Gitleaks, Trivy, OSV-Scanner et ZAP.
5. Cliquer sur un résultat pour ouvrir le fichier et la ligne concernés.

Semgrep détecte les vulnérabilités dans le code. Gitleaks recherche les secrets potentiels dans les fichiers courants. Trivy analyse les dépendances vulnérables, les mauvaises configurations et éventuellement une image Docker. OSV-Scanner valide les dépendances depuis les manifestes/lockfiles et fournit l’information de call analysis lorsqu’elle est disponible. ZAP analyse passivement l’application locale en cours d’exécution. Les valeurs des secrets sont masquées et ne sont jamais affichées dans Security Center.

## Comprendre l’affichage

Les résultats sont classés pour éviter une liste d’alertes difficile à lire :

1. **Scanner** : Semgrep ou Gitleaks, avec le nombre total de résultats.
2. **Fichier** : chemin concerné et nombre d’alertes dans ce fichier.
3. **Alerte** : titre, sévérité et numéro de ligne.

Survoler une alerte affiche l’outil, la règle, le fichier, la ligne et la référence CWE. Cliquer dessus ouvre directement le code concerné. Plusieurs alertes similaires peuvent provenir d’une même cause ; la corrélation et la déduplication avancées seront ajoutées dans une prochaine version.

Lorsque la même règle apparaît plusieurs fois dans un fichier, Security Center affiche une seule cause avec son nombre d’occurrences. Déplier cette cause montre toutes les lignes concernées. Ce regroupement améliore la lecture sans supprimer les résultats bruts du scanner.

Le dashboard affiche également les corrélations multi-outils. Une confiance `high` signifie que plusieurs outils ciblent le même fichier, des lignes proches et la même CWE. Une confiance `medium` entre ZAP et le code reste une hypothèse tant que le mapping précis entre l’endpoint HTTP et le contrôleur source n’est pas disponible.

## Suivre une alerte

Faire un clic droit sur une alerte puis choisir **Security Center: Changer le statut** :

- `Nouvelle` : résultat qui n’a pas encore été examiné ;
- `Confirmée` : vulnérabilité validée ;
- `Faux positif` : alerte non exploitable ou incorrecte ;
- `Risque accepté` : vulnérabilité connue temporairement acceptée ;
- `Corrigée` : correction appliquée, en attente ou après validation.

Les statuts sont conservés dans le stockage du workspace et restaurés lors du prochain scan grâce à l’identifiant stable de l’alerte. Les faux positifs et les alertes corrigées restent visibles pour la traçabilité, mais ne sont plus publiés dans **Problems** et ne contribuent plus au score de risque actif.

Un scanner reste visible même lorsqu’il ne détecte rien : `0 résultat(s) • terminé` signifie que l’analyse a réussi. La mention `échec` signifie que le scanner n’a pas pu terminer ; survoler son nom affiche la cause.

## Appliquer une correction Semgrep proposée

Lorsqu’une règle Semgrep fournit elle-même une correction native, faire un clic droit sur l’alerte puis choisir **Security Center: Appliquer la correction Semgrep proposée**. Security Center vérifie que le fichier est toujours dans le workspace et que le fragment n’a pas changé depuis le scan, ouvre un aperçu diff, puis demande confirmation avant d’écrire. Après application et enregistrement, Semgrep est relancé seul pour vérifier le résultat. Si la règle ne fournit aucun `fix`, Security Center refuse la modification au lieu d’inventer du code.

## Proposer une correction avec Ollama local

1. Installer et démarrer Ollama localement.
2. Installer au moins un modèle de code avec la commande Ollama de votre choix.
3. Dans Security Center, cliquer **Ollama local** ou lancer **Security Center: Configurer Ollama local**, puis sélectionner un modèle détecté. `qwen2.5-coder:14b` est recommandé pour la qualité des corrections ; le 7B reste le mode plus léger.
4. La correction IA reçoit un contexte limité (imports, types et fonction autour du finding), déclare ses hypothèses et sa confiance, puis Security Center calcule une confiance indépendante.
5. Après confirmation du diff, Security Center relance le scanner concerné et uniquement le script `test` déclaré dans `package.json`. Si le finding persiste ou si les tests échouent, un rollback est proposé.
4. Faire un clic droit sur une alerte liée à un fichier puis choisir **Proposer une correction avec Ollama**.
5. Examiner le diff et confirmer uniquement si la correction est correcte.

Security Center envoie seulement le finding et environ 35 lignes autour de l’alerte, avec une limite de 16 000 caractères. `.env`, clés privées, credentials et secrets détectables sont exclus ou masqués. Ollama doit répondre avec un JSON structuré contenant un unified diff. Le patch est limité à un fichier existant du workspace : création, renommage, traversée de chemin et fichiers sensibles sont refusés. Aucune commande suggérée par le modèle n’est exécutée. Après application, le scanner concerné est relancé. **Rollback IA** restaure le dernier fichier modifié pendant la session VS Code.

## Fonctionnement avec Docker

L’extension ne construit pas d’image du projet. Elle monte temporairement le dossier en lecture seule dans les images officielles des scanners. Les conteneurs sont supprimés après le scan avec `--rm`; les images restent en cache dans Docker Desktop.

Images utilisées :

- `semgrep/semgrep`
- `zricethezav/gitleaks:latest`
- `aquasec/trivy:latest`
- `ghcr.io/google/osv-scanner:latest`
- `zaproxy/zap-stable`

Aucun compte Docker Hub n’est nécessaire pour télécharger ces images publiques.

## Configuration

```json
{
  "securityCenter.semgrep.command": "docker",
  "securityCenter.semgrep.config": "p/security-audit",
  "securityCenter.gitleaks.enabled": true,
  "securityCenter.gitleaks.command": "docker",
  "securityCenter.trivy.enabled": true,
  "securityCenter.trivy.command": "docker",
  "securityCenter.trivy.image": "bkimminich/juice-shop:latest",
  "securityCenter.osv.enabled": true,
  "securityCenter.zap.enabled": true,
  "securityCenter.zap.targetUrl": "http://127.0.0.1:3000",
  "securityCenter.scan.timeoutSeconds": 600
}
```

Docker est le mode par défaut afin de garantir le même environnement pour tous les utilisateurs et dans la CI/CD. Le mode `local` reste disponible pour un utilisateur avancé ayant installé les scanners séparément.

Sous Windows, l’extension sélectionne explicitement le contexte Docker Desktop `desktop-linux`. Les scanners sont exécutés successivement pour éviter que plusieurs téléchargements d’images ou de bases de vulnérabilités se bloquent entre eux.

Security Center lance directement chaque scanner avec Docker et affiche l’outil en cours : Semgrep, Gitleaks, Trivy, OSV-Scanner, puis ZAP. Si Docker Desktop est fermé ou bloqué, le scanner concerné passe à l’état `échec` et son message fournit la cause.

Pour la sécurité, ZAP accepte uniquement `localhost`, `127.0.0.1` ou `::1`. N’utilisez le DAST que sur une application que vous êtes autorisé à tester.

Sur Windows, le mode recommandé est `zap.mode: auto`. Security Center détecte automatiquement `C:\Program Files\ZAP\Zed Attack Proxy\zap.bat`, démarre un daemon local protégé par une clé API aléatoire, exécute le scan via REST puis arrête le daemon. Utilisez `zap.mode: docker` uniquement pour forcer explicitement l’ancien fonctionnement conteneurisé.

Pour un scan actif JWT, configurez `zap.active: true` et `zap.auth_login` dans `security-center.yml`, puis définissez les identifiants uniquement dans le terminal qui lance VS Code :

```powershell
$env:SECURITY_CENTER_ZAP_USERNAME='compte-de-test-local'
$env:SECURITY_CENTER_ZAP_PASSWORD='mot-de-passe-du-compte-de-test'
code .
```

Security Center effectue le login local, extrait le jeton selon `zap.auth_token_path`, puis le transmet à ZAP via un fichier d’environnement temporaire supprimé après le scan. Le mot de passe et le JWT ne sont pas écrits dans le rapport ni placés dans les arguments Docker. Un scan actif exécute de vraies attaques : une confirmation et une justification auditées restent obligatoires.

Les résultats ZAP sont regroupés par type de vulnérabilité, puis par endpoints concernés. La fiche développeur présente une explication contextualisée, l’impact possible, la priorité, la confiance, la preuve et un plan de correction. Les détails originaux du scanner restent disponibles dans une section technique repliable. Les balises HTML des messages ZAP sont nettoyées et un seul onglet de détails est réutilisé lorsque vous cliquez sur plusieurs alertes.

## Importer et rejouer une capture HTTP

Le dashboard contient trois boutons visibles :

- **Ouvrir le dashboard complet** ;
- **Lancer l’analyse complète** ;
- **Importer une capture HTTP (HAR)** ;
- **Rejouer un scénario HTTP**.

La section **Tests HTTP guidés** affiche le nombre de scénarios enregistrés et explique les cinq étapes Capture, Protection, Replay, Comparaison et Validation.

La vue de la barre latérale sert de résumé. **Ouvrir le dashboard complet** affiche la même interface dans un grand onglet de l’éditeur VS Code. La page complète est responsive : les cartes, actions et étapes HTTP utilisent plusieurs colonnes lorsque la largeur disponible le permet. Les deux vues restent synchronisées pendant les scans et après l’import d’une capture.

Lorsque vous lancez une analyse, la section **Pipeline d’analyse** affiche :

```text
Start → Semgrep → Gitleaks → Trivy → OSV-Scanner → ZAP → End
```

Chaque cercle change selon l’état : gris en attente, bleu en cours, vert terminé et rouge en échec. La durée de chaque scanner apparaît après son exécution et la durée globale apparaît sous `End`. Sur une barre latérale étroite, le pipeline peut défiler horizontalement.

1. Exporter une navigation locale au format HAR depuis le navigateur ou un proxy.
2. Lancer **Security Center: Importer une capture HTTP (HAR)**.
3. Les requêtes locales sont normalisées et enregistrées dans le backend.
4. Lancer **Security Center: Rejouer un scénario HTTP**.
5. Sélectionner une requête `GET`, `HEAD`, `POST`, `PUT` ou `PATCH`.
6. Si une correction est au statut `fixed`, la sélectionner pour relier le replay à cette vulnérabilité.
7. Pour `POST/PUT/PATCH`, autoriser les écritures locales une fois pour la session VS Code. Les replays suivants sont audités automatiquement sans interrompre les tests.
8. Consulter la preuve avant/après : statut HTTP, empreinte du corps et contenu de la nouvelle réponse.

Les en-têtes `Authorization`, `Cookie`, `Set-Cookie`, `Proxy-Authorization` et `X-API-Key` sont remplacés par `[REDACTED]` avant stockage. Les entrées visant une adresse non locale sont rejetées. `POST/PUT/PATCH` demandent une autorisation une fois par session et sont ensuite journalisés automatiquement, sans demander de justification. Le corps est limité à 256 Kio. `DELETE` reste toujours interdit. Le résultat est également audité lorsqu’il est lié à une correction ou qu’il modifie potentiellement des données.

Le replay apporte une preuve complémentaire, mais ne transforme pas automatiquement le statut `fixed` en `validated`. La validation définitive exige que le scanner concerné termine un nouveau scan et confirme la disparition de l’alerte.

La future extension Burp Montoya utilisera la même API `/api/v1/http-scenarios` avec la source `burp`. Les secrets nécessaires aux tests authentifiés seront conservés séparément dans le SecretStorage de VS Code, pas dans le rapport partagé.

## Erreurs fréquentes

## Slack et Jira

Lancer **Security Center: Configurer Slack ou Jira** depuis la palette de commandes. Slack demande une URL de webhook entrant ; Jira demande l’URL du site Cloud, l’adresse du compte, la clé du projet et un jeton API. Le webhook et le jeton sont conservés uniquement dans `SecretStorage`. Les intégrations sont désactivées par défaut et ne s’exécutent que lorsqu’un finding passe explicitement au statut `confirmed`. Une panne Slack/Jira ne bloque ni le triage ni les scans ; elle est inscrite dans le journal de sortie.

Pour désactiver une intégration, décocher `securityCenter.notifications.slack.enabled` ou `securityCenter.notifications.jira.enabled` dans les réglages du workspace.

- **Docker API / pipe introuvable** : démarrer Docker Desktop et attendre que le moteur soit prêt.
- **Cannot create auto config when metrics are off** : utiliser `p/security-audit` comme configuration Semgrep.
- **Scan partiel** : un scanner a échoué, mais les résultats des autres scanners restent disponibles.
- **Premier scan lent** : Docker télécharge les images lors de la première utilisation.

## Sécurité et confidentialité

Les analyses sont exécutées localement. Le code n’est pas envoyé par l’extension vers un serveur applicatif. Vérifier néanmoins la politique de confidentialité de toute règle ou service externe activé.
