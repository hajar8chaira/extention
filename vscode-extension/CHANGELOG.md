# Changelog

## Non publié

- Inventaire d'API dynamique : endpoints canoniques construits depuis le trafic reellement observe (Burp, ZAP, HAR, OpenAPI), avec methode, hote, route normalisee, parametres de query, types de contenu, authentification observee, premiere et derniere vue, nombre de requetes, findings et dernier code de statut.
- Normalisation conservatrice des identifiants : `/users/123` et `/users/456` deviennent `/users/{id}` sur la forme du segment ; `/products/shoes` et `/products/hats` restent deux endpoints. Une fusion par observation exige au moins trois valeurs distinctes ET un segment parent — un inventaire qui fusionne trop masque des endpoints.
- Couverture dynamique a etats ordonnes : NOT_TESTED, OBSERVED, PASSIVELY_ANALYZED, REPLAYED, ACTIVELY_TESTED. Apparaitre dans le trafic d'un proxy n'est jamais compte comme un test, et un inventaire vide donne 0 % et non 100 %.
- Comparaison de replay : statut, type de contenu, duree, taille, presence des en-tetes de securite. Les valeurs d'en-tete ne sont jamais diffusees — un diff de Set-Cookie afficherait une session — et un corps trop volumineux n'est pas compare plutot que conclu a tort.
- Retest cible avec verdicts fondes sur la condition de securite du finding : VALIDATED, STILL_PRESENT ou INCONCLUSIVE. Un statut HTTP ne vaut jamais verdict ; sans verification applicable, la reponse est INCONCLUSIVE et la preuve precedente est conservee.
- Cycle de vie de retest verrouille : FOUND, FIX_APPLIED, RETESTING puis un verdict. Passer directement a VALIDATED est refuse — c'est exactement la fausse validation a empecher.
- Profils d'authentification DAST (bearer, cookie, en-tete personnalise) : le secret vit dans le SecretStorage sous une cle derivee, jamais dans le profil, les reglages, le HTML ni l'historique. Un profil refuse toute cle de forme credential. Un jeton configure ne suffit pas a revendiquer une couverture authentifiee : il faut une session validee et au moins un endpoint protege atteint.
- Sante Ollama unifiee : nouveau module `src/ai/ollama-health.js` distinguant NOT_CONFIGURED, OFFLINE, UNREACHABLE, NO_MODELS, MODEL_MISSING, READY et ERROR. La verite d'execution vient de `/api/tags`, jamais de la configuration : un modele nomme dans les reglages est une preference, pas un fait.
- Taxonomie d'erreurs Ollama : OLLAMA_OFFLINE, MODEL_NOT_FOUND, NO_MODELS, TIMEOUT, CANCELLED, INVALID_RESPONSE, INFERENCE_ERROR, chacune avec une phrase qui nomme l'action suivante. Aucun message de transport brut, aucun corps HTTP, aucune trace technique n'atteint l'utilisateur.
- Le health check ne fait jamais d'inference : lister les modeles repond a la question. Une inference minimale (un seul token) n'a lieu que sur demande explicite, et c'est le seul endroit ou une latence est affichee.
- Selection de modele par role deterministe et explicite : fast 3b, standard 7b, advanced 14b, sans les exiger. Un modele configure et installe gagne toujours ; toute substitution est signalee (`preference_substituted`, `code_model_substituted`, `unrelated_substituted`) plutot que silencieuse.
- Metadonnees de modele normalisees depuis `/api/tags` : taille, nombre de parametres, quantification, famille. Le digest n'est pas expose.
- Nouvelle commande `securityCenter.checkOllama` : statut, serveur, version, modeles installes avec leur taille, modele selectionne et sa disponibilite, plus une action facultative de test d'inference annulable.
- Aucun telechargement automatique de modele : la commande `ollama pull` est affichee et copiable, jamais executee, et son argument est neutralise contre l'injection.
- Boucle Jenkins complete : le CLI produit un rapport CI normalise (`--ci-report`), le Jenkinsfile l'archive meme quand le gate refuse, et l'extension le relit depuis les artefacts du build pour afficher le VRAI verdict Policy Gate de ce build, ses raisons de blocage, l'etat de chaque scanner et les preuves supply chain.
- Contrat de rapport CI versionne (`schemaVersion`), projection du resultat existant : aucun finding brut, aucun secret, 1,4 Kio contre 15,7 pour le rapport complet. Valide en entree — taille plafonnee, JSON defensif, schema verifie, cles de pollution de prototype retirees.
- Identite a trois branches workspace / build / rapport. Un rapport produit depuis un autre commit que celui du build est INCOHERENT : son verdict n'est pas attribue au build, et encore moins au workspace.
- Etats CI explicites : REPORTED, NOT_REPORTED, INVALID, UNAVAILABLE. Aucun n'est rendu comme PASS ni comme 0 finding, et le verdict local n'est jamais substitue.
- Test de connexion non destructif : CONNECTED, AUTH_FAILED, FORBIDDEN, JOB_NOT_FOUND, UNREACHABLE, ERROR. Aucun corps HTML Jenkins brut n'est reaffiche.
- Decouverte d'artefact durcie : traversee, chemin absolu et chemin Windows refuses ; chaque segment d'URL encode ; numero de build valide exige.
- Le deploiement n'est jamais deduit du succes du build : l'etat reste « indisponible » tant que l'API lue ne le prouve pas.
- Integration Jenkins / CI-CD : la meme politique projet decide en local et en CI. Nouveau module client Jenkins, page Security Delivery, commandes `openSecurityDelivery`, `configureJenkins` et `openJenkinsfileTemplate`, et modele `templates/Jenkinsfile` ou le deploiement est bloque par le Policy Gate.
- Jeton d'API Jenkins conserve dans le SecretStorage de VS Code uniquement : jamais dans settings.json, jamais dans une URL, jamais dans le HTML de la page, jamais dans un evenement d'audit. Une URL Jenkins contenant des identifiants est refusee, et les corps de reponse d'erreur ne sont jamais reaffiches.
- Correlation commit workspace / commit du build : SAME, DIFFERENT ou UNKNOWN. Aucune correspondance n'est affirmee sans les deux commits, et un build portant un autre commit est signale comme ne concernant pas le code ouvert.
- Comparaison de scans : ajout de REGRESSED — un finding precedemment valide, corrige, accepte ou classe faux positif qui reapparait ouvert. Un finding jamais vu reste NOUVEAU.
- `findingIdentity` ne peut plus renvoyer `undefined` : deux findings sans empreinte ni identifiant se confondaient et paraissaient etre le meme resultat persistant.
- Packaging : `.vscodeignore` exclut desormais `.codex-backups`, `.codegraph`, `.env`, les cles privees et les VSIX construits.
- Identite de campagne Dynamic Security : chaque execution ZAP et chaque session de capture Burp recoivent un identifiant unique et triable, avec cible, mode, horodatages, cycle de vie et statistiques. Transactions et findings sont attribues a la campagne qui les a produits.
- Cycle de vie ZAP reel : STARTING, SPIDERING, PASSIVE_WAIT, ACTIVE_SCANNING, COLLECTING_RESULTS, COMPLETED, PARTIAL, CANCELLED, FAILED. Chaque pourcentage vient de `spider/view/status`, `ascan/view/status` ou `pscan/view/recordsToScan` — la valeur etait lue puis jetee, elle atteint maintenant le modele. Aucune progression n'est produite par un minuteur.
- Attente reelle de la file de scan passif via `pscan/view/recordsToScan`. Si la vue est indisponible, l'etape est signalee indisponible et jamais affichee comme satisfaite.
- Session de capture Burp : la connectivite du connecteur et les donnees capturees sont deux faits distincts. Un connecteur deconnecte avec des requetes stockees devient un historique, jamais une capture en direct, et l'absence d'horodatage cote backend est dite au lieu d'etre comblee.
- Persistance via le cache de scan local existant — aucun second mecanisme : une campagne survit a un rechargement de VS Code. Un cache anterieur a l'identite de campagne est charge comme lot legacy explicitement non attribue.
- Les transactions persistees ne contiennent que des metadonnees : aucun corps de requete, en-tetes et valeurs de query passes par le sanitizer unique, URL stockee assainie elle aussi, et seuls les noms de parametres conserves.
- Security Companion relie aux evenements reels manquants : progression du scan par scanner (comptee, jamais mise en sequence fictive), issue du scan (terminee / partielle / echouee), etat de la correction (disponible, appliquee, verifiee, echouee), preuves supply chain (SBOM, provenance, signature, verification) et etat du connecteur Burp.
- Les echecs de scanner deviennent une phrase courte et actionnable : « Jeton Snyk manquant », « SonarQube injoignable », « Docker indisponible », « Gitleaks n'est pas installe ». Un echec non reconnu ne recopie jamais le texte brut, donc ni jeton ni chemin absolu ne peut fuiter dans la bulle.
- Echelle de priorite recentree : critique du fichier courant, findings du fichier, erreur du moteur, politique bloquante, sante des scanners, analyse en cours, correction, scan problematique, supply chain, fichier propre, compte rendu de scan, desactive, repos.
- Un scan partiel ou echoue prime sur « ce fichier est propre » ; un scan reussi reste en ligne secondaire pour ne pas voler le titre au fichier courant, et son total n'est jamais annonce deux fois.
- Les bulles informatives (compte rendu de scan, preuve supply chain, fichier propre) s'effacent apres 6 s par animation CSS ; une alerte, un blocage ou une erreur reste jusqu'au changement d'etat.
- Cliquer le compagnon mene la ou pointe son message : le finding, la configuration du scanner concerne, ou le Security Pipeline. Aucune action n'est une remediation, et aucun modele n'est appele.
- Security Companion compact en deux modes visuels, alimentés par le même modèle partagé : `full` sur la page Live Security (mascotte 72x90) et `compact` sur le dashboard, ses pages (Findings, Scans, Dynamic Security, Analytics) et le Security Pipeline (mascotte 44x56).
- Contraste de la bulle corrige : le fond et le texte viennent desormais de la meme paire de theme VS Code (`editorHoverWidget-background` / `editorHoverWidget-foreground`), chaque couleur ayant un repli litteral.
- La bulle est limitee a 220 px et deux lignes, tronquee visuellement au-dela avec le texte complet expose en infobulle.
- Couche flottante non bloquante : `pointer-events:none` sur le conteneur, `auto` uniquement sur la mascotte, la bulle et les actions. Niveau d'empilement documente (15) : au-dessus du contenu epingle, sous les confirmations modales et les popovers.
- Zone de securite responsive (24/28 px en large, 16/20 en moyen, 10/14 en etroit) ; sous 620 px la mascotte rapetisse et la bulle se tait sauf en avertissement, critique ou erreur ; sous 420 px de hauteur, mascotte et badge seulement.
- Priorite des messages recentree sur le fichier courant : un finding Live passe devant les faits projet, et « Dernier scan complet : N findings » devient une ligne secondaire au lieu de servir de titre sur la page Live Security.
- Le compagnon de la sidebar du dashboard reste absent, et celui du dashboard ne se trouve plus dans `.operational-banner` — que `body.surface-full` masque, ce qui le rendait invisible.
- Policy Gate rendu utilisable : cinq états distincts — `NOT_CONFIGURED`, `PASS`, `WARN`, `BLOCK`, `ERROR`. Une politique absente ou illisible n'est plus rapportée comme un `PASS`.
- Onglet « Policy Gate » dans Security Pipeline : configuration des règles sans écrire de YAML, verdict expliqué violation par violation (sévérité, priorité, atteignabilité, palier de corrélation, scanners d'origine, fichier:ligne), règles appliquées en français avec leur clé YAML, et bouton « Avancé — ouvrir security-center.yml ».
- `security-center.yml` reste la seule source de vérité : l'interface écrit uniquement les blocs `gate:` et `supply_chain:`, valide avant et après écriture, écrit de façon atomique, et préserve les autres sections ainsi que les commentaires situés en dehors des blocs réécrits.
- « Ré-évaluer la politique » rejoue le moteur de politique sur le scan déjà terminé, sans relancer aucun scanner. Le verdict reste attaché à son `scanId`, et une politique modifiée depuis le scan est signalée comme telle au lieu de recalculer l'historique en silence.
- Politique de départ créée uniquement sur demande explicite ; elle complète un fichier sans `gate:` sans jamais remplacer des règles existantes.
- `security-center.yml` accepte désormais les listes YAML en bloc (`- CRITICAL`) en plus des listes en ligne (`[CRITICAL]`).
- `fail_on_severity` applique le seuil le plus permissif de la liste quel que soit son ordre : `[CRITICAL, HIGH]` bloque bien les HIGH.
- Un finding ne produit plus qu'une seule violation, avec la règle la plus spécifique : un secret est rapporté comme secret et le décompte reflète le nombre de vrais problèmes.
- Sortie CLI orientée CI (`POLICY GATE: <état>`, violations avec priorité, atteignabilité et scanners, puis `Exit code:`) — aucune valeur de secret n'est réimprimée. Codes de sortie : 0 accepté, 1 refusé par la politique, 2 échec d'exécution ou politique illisible.
- Audit du Policy Gate enrichi du `scanId`, de l'empreinte des règles et du caractère manuel d'une ré-évaluation.
- Le Security Companion annonce le verdict du pipeline sans jamais l'évaluer lui-même : blocage, politique invalide, ou politique respectée.
- SonarQube intégré comme scanner de première classe : modes `auto`, `local` et `docker`, preflight du serveur, attente bornée du traitement Compute Engine, récupération paginée des issues et des security hotspots, normalisation dans le modèle de finding commun.
- Jeton SonarQube conservé dans le SecretStorage de VS Code, transmis par variable d’environnement ou `--env-file` et masqué dans tous les messages.
- `docker-compose.sonarqube.yml` pour lancer SonarQube Community Build en local sur `127.0.0.1:9000`.
- Snyk intégré comme scanner de première classe : modes `auto`, `local` et `docker` (image officielle `snyk/snyk:linux`), capacités Snyk Open Source (SCA), Snyk Code (SAST) et Snyk IaC normalisées dans le modèle de finding commun, avec empreintes stables indépendantes du numéro de ligne.
- Installation locale gérée du CLI Snyk depuis `downloads.snyk.io`, vérifiée par l’empreinte SHA-256 officielle et installée dans le stockage privé de l’extension, sans droit administrateur ni modification du PATH système.
- Jeton Snyk conservé dans le SecretStorage de VS Code, transmis uniquement par variable d’environnement et masqué dans les journaux, l’interface, les findings et les erreurs.
- Snyk Code ou Snyk IaC indisponible pour le compte n’invalide plus l’analyse : la capacité est signalée explicitement et Snyk Open Source continue de s’exécuter.
- Pipeline de décision DevSecOps : corrélation V2 (SCA, SAST, IaC, DAST↔SAST par mapping de routes réelles), moteur d’atteignabilité, priorisation déterministe expliquée et Policy Gate PASS/WARN/BLOCK, partagés à l’identique par l’extension et le CLI headless.
- Nouvelle page « Security Pipeline » avec onglets Pipeline, Corrélations, Reachability, Priorités et Supply Chain. Le dashboard et la page Configuration des scanners restent inchangés dans leur rôle.
- SBOM promu en artefact du pipeline (CycloneDX, digest, comptage de composants), provenance in-toto v1 / SLSA Provenance v1 (structure) et signature Cosign locale avec clé protégée par SecretStorage.
- Security Intelligence exécutée automatiquement à la fin de chaque analyse : corrélation, atteignabilité et priorisation alimentent le dashboard, la page Security Pipeline, l’historique et le snapshot sans action manuelle. Un échec de cette couche est signalé explicitement et ne supprime aucun résultat de scanner.
- Atteignabilité exposée avec le vocabulaire REACHABLE / POTENTIALLY_REACHABLE / NOT_REACHABLE / UNKNOWN, chaque verdict portant statut, confiance, preuves et explication.
- Priorités exprimées en P0/P1/P2/P3 avec score déterministe, facteurs nommés et explication lisible.
- Groupes de corrélation dotés d’un identifiant stable, d’un titre, du nombre de findings et d’un finding canonique — les résultats d’origine de chaque scanner restent tous consultables.
- `security-center.yml` accepte une section `gate:` (`fail_on_severity`, `warn_on_severity`, `block_secrets`, `priority_threshold`, `require_sbom`) et une section `supply_chain:` — purement additives.

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
