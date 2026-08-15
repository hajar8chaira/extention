# Rapport de validation réelle — 7 août 2026

## Environnement

- Docker Engine 29.2.1.
- Backend FastAPI exposé sur `127.0.0.1:8765`.
- OWASP Juice Shop officiel exposé uniquement sur `127.0.0.1:3000`.
- Cible source : `test-application/juice-shop`.
- Scan enregistré dans SQLite avec l’identifiant `13`.
- Rapport vérifiable : `security-reports/2026-08-07T16-36-24-016Z/`.

## Résultats observés

| Scanner | Résultats normalisés | Durée |
|---|---:|---:|
| Semgrep | 7 | 208,0 s |
| Gitleaks | 66 | 8,4 s |
| Trivy | 6 | 109,7 s |
| OSV-Scanner | 0 | 3,2 s |
| OWASP ZAP | 34 | 102,6 s |
| **Total dédupliqué** | **113** | **432,0 s environ** |

Répartition : 1 critique, 7 élevées, 73 moyennes, 14 faibles, 11 informatives et 7 `WARNING` Semgrep.

## Interprétation précise

### Confirmé par présence directe dans le code

- Gitleaks trouve une clé privée dans `lib/insecurity.ts:21` et quatre secrets génériques dans des fichiers de production. Les valeurs sont masquées (`REDACTED`). Cela confirme la présence de données ressemblant fortement à des secrets ; cela ne prouve pas qu’elles donnent accès à un service externe actif.
- Semgrep trouve notamment un secret JWT codé en dur dans `lib/insecurity.ts:54`, une redirection potentiellement contrôlée dans `routes/redirect.ts:19` et des constructions XSS potentielles dans `routes/videoHandler.ts:57` et `:71`.
- 61 des 66 alertes Gitleaks sont classées dans des fichiers de test. Elles restent des preuves de scanner, mais ne doivent pas être présentées comme 61 secrets de production.

### Confirmé dynamiquement

- ZAP a réellement observé `@angular/core 20.3.18` dans le JavaScript servi et a associé `CVE-2026-52725`, `CVE-2026-50557` et `CVE-2026-54267`.
- La version 20.3.18 appartient à la plage affectée publiée pour CVE-2026-50557, corrigée en 20.3.22. L’exposition du composant est confirmée ; l’exploitabilité dans le contexte exact de Juice Shop nécessite encore un scénario ciblé.
- ZAP relève aussi cinq absences de CSP, cinq configurations CORS permissives, cinq en-têtes Feature-Policy obsolètes et plusieurs alertes de cache/en-têtes. Ce sont des observations HTTP réelles, pas nécessairement des vulnérabilités exploitables isolément.

### Résultats négatifs et limites

- OSV-Scanner n’a produit aucun finding. Cela signifie « aucune vulnérabilité résolue par OSV dans les manifests analysés », pas « aucune dépendance vulnérable ».
- Trivy a produit six mauvaises configurations Docker, mais aucune CVE de dépendance dans ce passage source. Deux alertes élevées concernent `test/smoke/Dockerfile`, donc le contexte de test.
- La corrélation automatique a produit zéro association. ZAP voit des URL de bundles et Semgrep des fichiers sources, sans mapping bundle/route/contrôleur. Inventer une corrélation aurait été trompeur ; ce mapping reste à implémenter.
- Juice Shop est volontairement vulnérable. Les résultats démontrent la détection et la normalisation, pas l’état de sécurité d’une application de production.

## Validation fonctionnelle

- API `/health`, historique, détail de scan et exports JSON/HTML vérifiés sur le conteneur réel.
- Export HTML du scan 13 : HTTP 200, 22 078 octets et nom de fichier fourni par `Content-Disposition`.
- 58 tests Node réussis et vérification syntaxique de tous les modules réussie.
- 4 tests FastAPI/SQLite réussis : stockage, historique, export échappé, triage persistant, validation des statuts, cible Burp locale et heartbeat.
- L’annulation par `AbortController` a été testée sur Semgrep : `Scan Semgrep annulé.`.
