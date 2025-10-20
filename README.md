# Intranet RH - Demo (HackBench)

## But
Application : intranet RH minimal volontairement vulnérable.  
Utilisez-la uniquement dans le cadre du HackBench (48h). N'attaquez que votre propre instance.

## Endpoints
- `GET /` : page d'accueil + formulaire de recherche
- `POST /search` : recherche naïve dans `data/users.txt`
- `GET /admin?token=...` : endpoint admin simulé (token en clair)
- `GET /flag` : télécharge le flag pédagogique

## Objectifs pédagogiques
1. Trouver et documenter les vulnérabilités (ex : recherche non sécurisée, token en clair).  
2. Récupérer le flag (preuve) et documenter la méthode (commands.txt, captures).  
3. Proposer et implémenter des correctifs (validation input, stockage sécurisé du token, auth).

## Déploiement sur Replit
1. Fork / Importer ce repo dans Replit (Import from GitHub).  
2. Cliquer sur **Run**.  
3. Récupérer l'URL publique fournie par Replit (ex : `https://<votre-projet>.<votre-compte>.repl.co`).

## Règles
- Vous ne testez que votre instance.  
- Documentez **toutes** les commandes exécutées dans `evidence/commands.txt`.  
- Déclarez toute utilisation d'IA (outil + prompt) dans votre rapport.

## Remédiations attendues (suggestions)
- Ajout d'une authentification véritable (session + mot de passe hashed).  
- Validation stricte des entrées/sanitization.  
- Ne pas stocker token admin en clair dans l'URL.
