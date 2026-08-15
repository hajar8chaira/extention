# Security Center Connector for Burp Suite

Ce connecteur supprime le besoin d’exporter manuellement un fichier HAR.

## Construire le connecteur

Dans PowerShell :

```powershell
cd C:\Users\hajar\Desktop\pfa-start\burp-extension
.\build.ps1
```

Le JAR est créé dans `build\security-center-burp.jar`.

## Charger le connecteur dans Burp

1. Démarrer le backend Security Center sur `http://127.0.0.1:8765`.
2. Ouvrir Burp Suite.
3. Aller dans **Extensions > Installed > Add**.
4. Choisir le type **Java**.
5. Sélectionner `build\security-center-burp.jar`.
6. Ouvrir l’onglet **Security Center** et tester la connexion.
7. Laisser **Capture automatique des requêtes locales** activée.
8. Naviguer normalement dans l’application locale via Burp Proxy.

Les requêtes et réponses locales sont envoyées automatiquement au backend. Le clic droit
**Envoyer vers Security Center** reste disponible pour transmettre manuellement une requête.

Le MVP accepte uniquement `localhost`, `127.0.0.1` et `::1`, supprime les doublons d’une
même requête/réponse et masque les en-têtes sensibles avant envoi. L’utilisateur peut
désactiver la capture automatique à tout moment dans l’onglet Security Center de Burp.
