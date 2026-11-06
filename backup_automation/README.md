# Automatisation des sauvegardes FTD

FDM sait très bien créer une sauvegarde à la demande, mais il ne sait pas la
planifier tout seul, ni l'envoyer ailleurs que sur le boîtier lui-même. Les
sauvegardes restent stockées localement, ne sont pas gardées très longtemps,
et disparaissent carrément lors d'une mise à jour. C'est exactement ce que
cet outil vient corriger : il déclenche une sauvegarde sur le FTD, la
récupère, puis l'envoie vers un serveur FTP (ou FTPS) de votre choix -- de
quoi la mettre tranquillement sur une tâche planifiée (cron la nuit, tâche
planifiée Windows, etc.).

Tout ce qu'il faut pour le faire fonctionner est déjà dans ce dossier, pas
besoin du reste de l'outil de migration.

## Ce qu'il vous faut avant de commencer

1. **Une machine pour l'exécuter.** Pas le FTD lui-même -- FDM ne peut pas
   lancer de scripts sur le boîtier. N'importe quel serveur ou poste avec
   Python 3 fait l'affaire, tant qu'il reste allumé et accessible pour les
   exécutions planifiées.
2. **Un accès réseau** depuis cette machine vers :
   - l'interface de gestion du FTD, en HTTPS (port 443) ;
   - votre serveur FTP/FTPS, sur le port 21 (et les ports de données en mode
     passif si votre pare-feu les filtre).
3. **Un compte FDM** avec accès à l'API -- le même genre de compte admin que
   celui utilisé pour se connecter à l'interface web.
4. **Un serveur FTP ou FTPS** que vous maîtrisez, avec un compte capable d'y
   écrire des fichiers.
5. **Un moyen de planifier** l'exécution sur votre machine -- `cron` sous
   Linux/macOS, le Planificateur de tâches sous Windows.
6. **FTP ou FTPS ?** À trancher avant de se lancer : le FTP classique envoie
   la sauvegarde en clair sur le réseau. Si ça pose problème chez vous,
   prenez un serveur compatible FTPS et activez `tls: true` dans la config.

## Installation

1. Python 3 installé, puis les deux dépendances :

   ```
   pip install -r requirements.txt
   ```

2. Dupliquez le fichier de config et remplissez-le avec vos propres
   valeurs :

   ```
   cp config.example.yaml config.yaml
   ```

   Dans `config.yaml` :
   - `ftd.host` / `username` / `password` : l'adresse de gestion du FTD et
     votre compte API FDM ;
   - `ftp.host` / `port` / `username` / `remote_dir` : les coordonnées de
     votre serveur FTP ;
   - `ftp.tls` : à `true` si votre serveur FTP gère le FTPS ;
   - gardez `options.dry_run: true` pour le premier essai, on y vient juste
     après.

3. Même chose pour les secrets :

   ```
   cp backup_secrets.example.yaml backup_secrets.yaml
   ```

   - `ftp_password` : le mot de passe du compte FTP ;
   - `encryption_key` (facultatif, mais conseillé) : chiffre le fichier de
     sauvegarde en lui-même, indépendamment du FTP.

   Ces deux fichiers (`config.yaml` et `backup_secrets.yaml`) contiennent de
   vrais identifiants -- à garder pour vous, jamais à partager ni déposer
   quelque part d'accessible.

## Lancer le script

**Un essai à blanc d'abord**, `dry_run: true` toujours actif :

```
python backup_to_ftp.py --config config.yaml
```

Rien n'est envoyé nulle part, le script se contente d'afficher ce qu'il
ferait. C'est le moment de vérifier que l'hôte et les chemins affichés
correspondent bien à ce que vous attendez.

**Puis pour de vrai** : passez `dry_run: false` et relancez la même
commande, en gardant un œil sur ce qui s'affiche. Cette fois, une
sauvegarde est réellement déclenchée sur le FTD, le script attend qu'elle se
termine, la télécharge, et l'envoie sur votre FTP. Faites tourner ça une
fois à la main avant de le planifier, pour être sûr que tout se passe bien
avec votre équipement.

Et si vous voulez en garder une copie à côté du script en plus de l'envoi :

```
python backup_to_ftp.py --config config.yaml --keep-local
```

## Le planifier

Une fois qu'un essai manuel passe sans accroc, on peut l'automatiser.
Exemple avec `cron` sous Linux, tous les jours à 2h du matin :

```
0 2 * * * cd /chemin/vers/backup_automation && python backup_to_ftp.py --config config.yaml >> backup.log 2>&1
```

Sous Windows, une tâche planifiée qui lance :

```
python C:\chemin\vers\backup_automation\backup_to_ftp.py --config config.yaml
```

avec "Démarrer dans" pointé sur le dossier `backup_automation`.

## Si ça coince

Relancez le script à la main (pas via la planification) et regardez ce qui
s'affiche -- chaque étape est annoncée au fur et à mesure (déclenchement,
attente, téléchargement, envoi), et l'erreur réelle s'affiche dès qu'une
étape rate. Quelques pistes à vérifier en premier :
- Cette machine arrive-t-elle à joindre le FTD en HTTPS, et le serveur FTP
  sur son port ?
- Les identifiants dans `config.yaml` et `backup_secrets.yaml` sont-ils bons
  et toujours valides ?
- Y a-t-il assez de place sur le disque pour stocker la sauvegarde le temps
  de l'envoyer ?
