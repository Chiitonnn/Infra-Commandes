DOCUMENTATION FINALE DU PROJET
Infrastructure Réseau Complète avec Sauvegarde Automatisée
📊 VUE D'ENSEMBLE DE L'INFRASTRUCTURE
text
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   FIREWALL      │────▶│   SERVEUR WEB   │────▶│   BACKUP        │
│   192.168.100.10│     │   192.168.100.50│     │   192.168.100.70│
│                 │     │   (Nginx HTTPS) │     │   (Sauvegarde)  │
└─────────────────┘     └─────────────────┘     └─────────────────┘
        │ 
        │                         
        ▼                         
┌─────────────────┐     
│  ADMIN SERVER   │     
│  192.168.100.60 │     
│   (Gestion)     │     
└─────────────────┘     
1. VÉRIFICATION INITIALE DE L'INFRASTRUCTURE
Objectif : Vérifier la configuration existante avant de commencer.

1.1 Sur Firewall (192.168.100.10)
bash
# Pourquoi : Vérifier que les clés SSH existent déjà pour les connexions entre serveurs
titou@firewall:~$ cat /etc/hosts
127.0.0.1 localhost
127.0.1.1 firewall

titou@firewall:~$ ls -la ~/.ssh/
total 32
drwx------  2 titou titou 4096 déc.   4 18:24 .
drwxr-x--- 15 titou titou 4096 déc.   4 22:42 ..
-rw-------  1 titou titou 1677 déc.   4 18:33 authorized_keys
-rw-------  1 titou titou  411 déc.   4 17:35 infra_key
-rw-r--r--  1 titou titou   96 déc.   4 17:35 infra_key.pub
-rw-------  1 titou titou 4196 déc.   4 22:16 known_hosts
-rw-------  1 titou titou 3218 déc.   4 18:24 known_hosts.old

# Pourquoi : Vérifier si des utilisateurs de sauvegarde existent déjà
titou@firewall:~$ cat /etc/passwd | grep -E "(backup|admin|user)"
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
sssd:x:110:113:SSSD system user,,,:/var/lib/sss:/usr/sbin/nologin
cups-pk-helper:x:112:114:user for cups-pk-helper service,,,:/nonexistent:/usr/sbin/nologin
hplip:x:116:7:HPLIP system user,,,:/run/hplip:/bin/false
backupuser:x:1001:1001::/home/backupuser:/bin/bash
1.2 Sur Backup Server (192.168.100.70)
bash
# Pourquoi : Vérifier que la structure de sauvegarde existe déjà
titou@backup-server:~$ ls -la /backup/
total 24
drwxr-xr-x  6 titou titou 4096 déc.   4 11:30 .
drwxr-xr-x 24 root  root  4096 déc.   4 11:30 ..
drwxr-xr-x  4 titou titou 4096 déc.   4 16:50 admin
drwxr-xr-x  4 titou titou 4096 déc.   4 16:50 firewall
drwxr-xr-x  2 titou titou 4096 déc.   4 11:35 logs
drwxr-xr-x  4 titou titou 4096 déc.   4 16:50 web
1.3 Sur ServerWeb (192.168.100.50)
bash
# Pourquoi : Identifier le service web en cours d'exécution (Apache ou Nginx)
titou@serveur-web:~$ sudo systemctl status nginx 2>/dev/null
● nginx.service - A high performance web server and a reverse proxy server
     Loaded: loaded (/usr/lib/systemd/system/nginx.service; enabled; preset: enabled)
     Active: active (running) since Thu 2025-12-04 19:10:07 CET; 14h ago

# Pourquoi : Vérifier la structure des sites web
titou@serveur-web:~$ ls -la /var/www/
total 12
drwxr-xr-x  3 root root 4096 oct.  21 10:10 .
drwxr-xr-x 15 root root 4096 oct.  21 10:10 ..
drwxr-xr-x  2 root root 4096 oct.  21 18:23 html

# Pourquoi : Vérifier les clés SSH autorisées pour les connexions
titou@serveur-web:~$ cat ~/.ssh/authorized_keys
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDwYqXxUftTdCQ4iQa4xnmx4c1GsQg7ilfL4+ytJ9glm titou@backup-server
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDEc0YK1THEUCERYB06GSDGsSbothD5tQSAkNCa9ZxE0 titou@firewall
1.4 Test des connexions SSH
bash
# Pourquoi : Tester que les connexions SSH fonctionnent entre tous les serveurs
titou@firewall:~$ ssh -i ~/.ssh/infra_key titou@192.168.100.50 "hostname && whoami"
serveur-web
titou
2. AUDIT DU FIREWALL (Configuration Firewalld)
Objectif : Documenter précisément la configuration du pare-feu principal.

bash
# Pourquoi : Connaître la version installée de firewalld
titou@firewall:~$ sudo firewall-cmd --version
2.1.1

# Pourquoi : Vérifier que le service est actif et en cours d'exécution
titou@firewall:~$ sudo systemctl status firewalld --no-pager --full
● firewalld.service - firewalld - dynamic firewall daemon
     Loaded: loaded (/usr/lib/systemd/system/firewalld.service; enabled; preset: enabled)
     Active: active (running) since Wed 2025-12-10 10:25:39 CET; 1h 50min ago

# Pourquoi : Voir toutes les interfaces réseau, leurs noms et leurs adresses IP
titou@firewall:~$ ip addr show
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
2: enp0s3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 08:00:27:7b:93:c5 brd ff:ff:ff:ff:ff:ff
    inet 10.0.2.15/24 brd 10.0.2.255 scope global dynamic noprefixroute enp0s3
       valid_lft 79759sec preferred_lft 79759sec
3: enp0s8: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 08:00:27:ad:a3:05 brd ff:ff:ff:ff:ff:ff
    inet 192.168.100.1/24 brd 192.168.100.255 scope global noprefixroute enp0s8
       valid_lft forever preferred_lft forever

# Pourquoi : Afficher la table de routage
titou@firewall:~$ ip route show
default via 10.0.2.2 dev enp0s3 proto dhcp src 10.0.2.15 metric 100
10.0.2.0/24 dev enp0s3 proto kernel scope link src 10.0.2.15 metric 100
192.168.100.0/24 dev enp0s8 proto kernel scope link src 192.168.100.1 metric 101

# Pourquoi : Obtenir une vue d'ensemble de TOUTES les zones définies dans firewalld
titou@firewall:~$ sudo firewall-cmd --list-all-zones
external (active)
  target: DROP
  interfaces: enp0s3
  services: ssh
  masquerade: yes
  forward-ports:
        port=80:proto=tcp:toport=80:toaddr=192.168.100.50
        port=2222:proto=tcp:toport=22:toaddr=192.168.100.60

internal (active)
  target: ACCEPT
  interfaces: enp0s8
  services: dhcp dns ssh
  ports: 873/tcp

# Pourquoi : Voir quelles zones sont actuellement utilisées
titou@firewall:~$ sudo firewall-cmd --get-active-zones
external
  interfaces: enp0s3
internal
  interfaces: enp0s8
public (default)

# Pourquoi : Afficher la configuration réelle et complète du pare-feu au niveau noyau
titou@firewall:~$ sudo nft list ruleset
table inet firewalld {
        chain filter_FORWARD {
                type filter hook forward priority filter + 10; policy accept;
                ct state { established, related } accept
                jump filter_FORWARD_POLICIES
        }
        # ... (configuration nftables complète)
}
3. CRÉATION DES SCRIPTS DE SAUVEGARDE
Objectif : Créer les scripts qui vont automatiser les sauvegardes.

3.1 Script Firewall (/home/titou/backup-firewall.sh)
Pourquoi : Sauvegarder la configuration critique du firewall.

bash
# Pourquoi : Créer un script automatisé pour sauvegarder toute la configuration critique
```
titou@firewall:~$ cat /home/titou/backup-firewall.sh
#!/bin/bash
# backup-firewall.sh - Sauvegarde complète du firewall
# Auteur: titou
# Date: 2025-12-05

# ================= CONFIGURATION =================
BACKUP_USER="titou"
BACKUP_IP="192.168.100.70"
BACKUP_DIR="/backup/firewall"
SSH_KEY="$HOME/.ssh/infra_key"
DATE=$(date +%Y-%m-%d_%H-%M-%S)
RETENTION_DAYS=7
LOG_FILE="/home/titou/backup-logs/firewall-$(date +%Y%m%d).log"

# ================= INITIALISATION =================
# Créer répertoire de logs
mkdir -p "$(dirname "$LOG_FILE")"

# Fonction de logging
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Fonction d'erreur
error_exit() {
    log "❌ ERREUR: $1"
    exit 1
}

log "✅ Début sauvegarde firewall"

# ================= VÉRIFICATIONS =================
log "1. Vérifications préalables..."

# Test connexion backup
if ! ping -c 2 "$BACKUP_IP" > /dev/null 2>&1; then
    error_exit "Backup server ($BACKUP_IP) inaccessible"
fi
log "   ✓ Backup server joignable"

# Test clé SSH
if [ ! -f "$SSH_KEY" ]; then
    error_exit "Clé SSH $SSH_KEY introuvable"
fi
log "   ✓ Clé SSH trouvée"

# ================= COLLECTE DONNÉES =================
log "2. Collecte des données..."
TEMP_DIR="/tmp/fw-backup-$DATE"
mkdir -p "$TEMP_DIR"

# 2.1 Configuration DNS
log "   - Configuration DNS (Bind9)"
sudo tar -czf "$TEMP_DIR/etc-bind.tar.gz" -C /etc bind/ 2>/dev/null
sudo cp /etc/resolv.conf "$TEMP_DIR/resolv.conf.backup" 2>/dev/null

# 2.1 Configurations réseau
log "   - Configurations réseau"
sudo mkdir -p "$TEMP_DIR/etc"
sudo cp -r /etc/netplan/ "$TEMP_DIR/etc/netplan/" 2>/dev/null
sudo cp /etc/hosts "$TEMP_DIR/etc/"
sudo cp /etc/resolv.conf "$TEMP_DIR/etc/"

# 2.2 Règles iptables
log "   - Règles iptables"
sudo iptables-save > "$TEMP_DIR/iptables-rules.v4"
sudo ip6tables-save > "$TEMP_DIR/iptables-rules.v6"

# 2.3 Services
log "   - Services système"
sudo systemctl list-units --type=service --state=running > "$TEMP_DIR/services-running.list"
sudo systemctl list-unit-files --type=service > "$TEMP_DIR/services-all.list"

# 2.4 SSH
log "   - Configuration SSH"
sudo cp -r /etc/ssh/ "$TEMP_DIR/etc-ssh/" 2>/dev/null
cp -r ~/.ssh/ "$TEMP_DIR/ssh-keys/" 2>/dev/null

# 2.5 Paquets installés
log "   - Liste des paquets"
sudo dpkg --get-selections > "$TEMP_DIR/installed-packages.list"

# 2.6 Fichiers importants
log "   - Fichiers divers"
sudo cp /etc/fstab "$TEMP_DIR/etc/" 2>/dev/null
sudo cp /etc/crontab "$TEMP_DIR/etc/" 2>/dev/null
ls -la /etc/cron.* > "$TEMP_DIR/cron-jobs.list" 2>/dev/null

# ================= CRÉATION ARCHIVE =================
log "3. Création de l'archive..."
ARCHIVE_NAME="firewall-backup-$DATE.tar.gz"
cd /tmp
sudo tar -czf "$ARCHIVE_NAME" -C "$TEMP_DIR" .
sudo chown titou:titou "$ARCHIVE_NAME"
SIZE=$(du -h "$ARCHIVE_NAME" | cut -f1)
log "   ✓ Archive créée: $ARCHIVE_NAME ($SIZE)"

# ================= TRANSFERT =================
log "4. Transfert vers backup server..."
scp -i "$SSH_KEY" -o StrictHostKeyChecking=no \
    "$ARCHIVE_NAME" \
    "$BACKUP_USER@$BACKUP_IP:$BACKUP_DIR/" 2>/dev/null

if [ $? -eq 0 ]; then
    log "   ✓ Transfert réussi"

    # Extraire sur le backup server
    ssh -i "$SSH_KEY" "$BACKUP_USER@$BACKUP_IP" \
        "mkdir -p '$BACKUP_DIR/$DATE' && \
         tar -xzf '$BACKUP_DIR/$ARCHIVE_NAME' -C '$BACKUP_DIR/$DATE' && \
         rm '$BACKUP_DIR/$ARCHIVE_NAME' && \
         ln -sfn '$BACKUP_DIR/$DATE' '$BACKUP_DIR/latest'" 2>/dev/null

    # Nettoyage rotation
    ssh -i "$SSH_KEY" "$BACKUP_USER@$BACKUP_IP" \
        "find '$BACKUP_DIR' -maxdepth 1 -type d -name '2*' -mtime +$RETENTION_DAYS -exec rm -rf {} \;" 2>/dev/null
    log "   ✓ Rotation appliquée (garder $RETENTION_DAYS jours)"
else
    error_exit "Échec du transfert"
fi

# ================= NETTOYAGE LOCAL =================
log "5. Nettoyage local..."
sudo rm -rf "$TEMP_DIR"
rm -f "$ARCHIVE_NAME"

# ================= VÉRIFICATION =================
log "6. Vérification..."
REMOTE_CHECK=$(ssh -i "$SSH_KEY" "$BACKUP_USER@$BACKUP_IP" \
    "if [ -d '$BACKUP_DIR/$DATE' ]; then echo 'OK'; else echo 'FAIL'; fi" 2>/dev/null)

if [ "$REMOTE_CHECK" = "OK" ]; then
    log "   ✓ Sauvegarde vérifiée sur backup server"
    log "✅ Sauvegarde firewall terminée avec succès"
else
    log "⚠️  Avertissement: Impossible de vérifier la sauvegarde"
fi

# Afficher résumé
echo ""
echo "================== RÉSUMÉ =================="
echo "Date:        $(date)"
echo "Source:      firewall (192.168.100.10)"
echo "Destination: backup (192.168.100.70)"
echo "Répertoire:  $BACKUP_DIR/$DATE"
echo "Taille:      $SIZE"
echo "Rétention:   $RETENTION_DAYS jours"
echo "Log:         $LOG_FILE"
echo "============================================"
```

titou@firewall:~$ chmod +x /home/titou/backup-firewall.sh
3.2 Test du script Firewall
bash
# Pourquoi : Vérifier que le script fonctionne correctement avant de continuer
titou@firewall:~$ /home/titou/backup-firewall.sh
[2025-12-05 09:32:28] ✅ Début sauvegarde firewall
[2025-12-05 09:32:29]    ✓ Backup server joignable
[2025-12-05 09:32:29]    ✓ Clé SSH trouvée
[2025-12-05 09:32:30]    ✓ Archive créée: firewall-backup-2025-12-05_09-32-28.tar.gz (44K)
[2025-12-05 09:32:31]    ✓ Transfert réussi
[2025-12-05 09:32:32]    ✓ Rotation appliquée (garder 7 jours)
[2025-12-05 09:32:33]    ✓ Sauvegarde vérifiée sur backup server
[2025-12-05 09:32:33] ✅ Sauvegarde firewall terminée avec succès
3.3 Script ServerWeb depuis Firewall
Pourquoi : Sauvegarder serverweb DEPUIS le firewall (architecture bastion).

bash
# Pourquoi : Créer un répertoire dédié pour les scripts
titou@firewall:~$ mkdir -p /home/titou/backup-scripts

# Pourquoi : Utiliser le firewall comme bastion SSH pour sauvegarder à distance
titou@firewall:~$ cat > /home/titou/backup-scripts/backup-serverweb-from-firewall.sh << 'EOF'
#!/bin/bash
SERVERWEB_IP="192.168.100.50"
SERVERWEB_USER="titou"
BACKUP_IP="192.168.100.70"
BACKUP_USER="titou"
BACKUP_DIR="/backup/web"
SSH_KEY="$HOME/.ssh/infra_key"
DATE=$(date +%Y-%m-%d_%H-%M-%S)
RETENTION_DAYS=7
LOG_FILE="/home/titou/backup-logs/web-$(date +%Y%m%d).log"

# Points clés :
# • Collecte à distance via SSH
# • Sites web (/var/www/html/)
# • Configuration Nginx
# • Fichiers système importants
# • Liste des paquets installés

log "✅ Début sauvegarde serverweb (depuis firewall)"
# ... (script complet)
EOF

titou@firewall:~$ chmod +x /home/titou/backup-scripts/backup-serverweb-from-firewall.sh
3.4 Script Admin-Server depuis Firewall
Pourquoi : Sauvegarder admin-server de la même manière.

bash
titou@firewall:~$ cat > /home/titou/backup-scripts/backup-adminserver-from-firewall.sh << 'EOF'
#!/bin/bash
ADMINSERVER_IP="192.168.100.60"
ADMINSERVER_USER="titou"
BACKUP_IP="192.168.100.70"
BACKUP_USER="titou"
BACKUP_DIR="/backup/admin"
SSH_KEY="$HOME/.ssh/infra_key"
DATE=$(date +%Y-%m-%d_%H-%M-%S)
RETENTION_DAYS=7
LOG_FILE="/home/titou/backup-logs/admin-$(date +%Y%m%d).log"

log "✅ Début sauvegarde admin-server (depuis firewall)"
# ... (script complet)
EOF

titou@firewall:~$ chmod +x /home/titou/backup-scripts/backup-adminserver-from-firewall.sh
4. OUTIL DE RESTAURATION (/home/titou/backup-scripts/restore-tool.sh)
Pourquoi : Avoir un outil simple pour restaurer des fichiers depuis les sauvegardes.

bash
# Pourquoi : Créer un outil en ligne de commande pour restaurer facilement
titou@firewall:~$ cat > /home/titou/backup-scripts/restore-tool.sh << 'EOF'
#!/bin/bash
VERSION="1.0"
BACKUP_IP="192.168.100.70"
BACKUP_USER="titou"
SSH_KEY="$HOME/.ssh/infra_key"
BACKUP_BASE="/backup"

# Fonctionnalités :
# - list : Lister les sauvegardes disponibles
# - content/show : Voir le contenu d'une sauvegarde
# - restore : Restaurer un fichier spécifique
# - status : Voir l'état du backup server

info() { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[SUCCÈS]${NC} $1"; }

case "$1" in
    list)
        list_backups "$2"
        ;;
    restore)
        restore_file "$2" "$3" "$4" "$5"
        ;;
    status)
        show_status
        ;;
    *)
        echo "🔧 OUTIL DE RESTAURATION - Version $VERSION"
        ;;
esac
EOF

titou@firewall:~$ chmod +x /home/titou/backup-scripts/restore-tool.sh
5. AUTOMATISATION AVEC CRON
Pourquoi : Automatiser les sauvegardes pour qu'elles se fassent sans intervention manuelle.

bash
# Pourquoi : Nettoyer l'ancien crontab avant de configurer le nouveau
titou@firewall:~$ crontab -r
titou@firewall:~$ crontab -l
no crontab for titou

# Pourquoi : Automatiser les sauvegardes pour qu'elles se fassent toutes seules la nuit
titou@firewall:~$ cat > /home/titou/backup-cron.txt << 'EOF'
# ============================================
# SAUVEGARDES - FIREWALL (192.168.100.10)
# ============================================

# 1. SAUVEGARDE COMPLÈTE - 2h00 tous les jours
0 2 * * * /home/titou/backup-scripts/backup-all.sh >> /home/titou/backup-logs/cron-all.log 2>&1

# 2. VÉRIFICATION - 6h00 tous les jours
0 6 * * * /home/titou/verify-backups.sh >> /home/titou/backup-logs/cron-verify.log 2>&1

# 3. SAUVEGARDE FIREWALL - Toutes les 6h
0 */6 * * * /home/titou/backup-firewall.sh >> /home/titou/backup-logs/cron-firewall.log 2>&1
EOF

titou@firewall:~$ crontab /home/titou/backup-cron.txt

# Pourquoi : Vérifier que l'automatisation est correctement configurée
titou@firewall:~$ crontab -l
# ============================================
# SAUVEGARDES - FIREWALL (192.168.100.10)
# ============================================

# 1. SAUVEGARDE COMPLÈTE - 2h00 tous les jours
0 2 * * * /home/titou/backup-scripts/backup-all.sh >> /home/titou/backup-logs/cron-all.log 2>&1

# 2. VÉRIFICATION - 6h00 tous les jours
0 6 * * * /home/titou/verify-backups.sh >> /home/titou/backup-logs/cron-verify.log 2>&1

# 3. SAUVEGARDE FIREWALL - Toutes les 6h
0 */6 * * * /home/titou/backup-firewall.sh >> /home/titou/backup-logs/cron-firewall.log 2>&1

# Planification :
# - 2h00 : Sauvegarde complète de tous les serveurs
# - 6h00 : Vérification des sauvegardes
# - Toutes les 6h : Sauvegarde du firewall (configurations critiques)
6. TESTS DE FONCTIONNEMENT
6.1 Test des sauvegardes
bash
# Pourquoi : Vérifier que la sauvegarde de serverweb fonctionne
titou@firewall:~$ /home/titou/backup-scripts/backup-serverweb-from-firewall.sh
[2025-12-05 10:16:10] ✅ Début sauvegarde serverweb (depuis firewall)
[2025-12-05 10:16:15] ✅ Sauvegarde serverweb terminée

# Pourquoi : Vérifier que la sauvegarde d'admin-server fonctionne
titou@firewall:~$ /home/titou/backup-scripts/backup-adminserver-from-firewall.sh
[2025-12-05 09:45:37] ✅ Début sauvegarde admin-server (depuis firewall)
[2025-12-05 09:45:43] ✓ Sauvegarde terminée
6.2 Vérification sur Backup Server
bash
# Pourquoi : Vérifier la structure des sauvegardes
titou@firewall:~$ ssh -i ~/.ssh/infra_key titou@192.168.100.70 "ls -la /backup/"
total 24
drwxr-xr-x  6 titou titou 4096 déc.   4 11:30 .
drwxr-xr-x 24 root  root  4096 déc.   4 11:30 ..
drwxr-xr-x  4 titou titou 4096 déc.   4 16:50 admin
drwxr-xr-x  4 titou titou 4096 déc.   4 16:50 firewall
drwxr-xr-x  2 titou titou 4096 déc.   4 11:35 logs
drwxr-xr-x  4 titou titou 4096 déc.   4 16:50 web

# Pourquoi : Vérifier que les liens symboliques "latest" pointent vers les dernières sauvegardes
titou@firewall:~$ ssh -i ~/.ssh/infra_key titou@192.168.100.70 "ls -la /backup/*/latest"
lrwxrwxrwx 1 titou titou 36 déc.   5 08:32 /backup/firewall/latest -> /backup/firewall/2025-12-05_09-32-28
lrwxrwxrwx 1 titou titou 35 déc.   5 09:13 /backup/web/latest -> /backup/web/2025-12-05_10-13-11
lrwxrwxrwx 1 titou titou 36 déc.   5 08:45 /backup/admin/latest -> /backup/admin/2025-12-05_09-45-37
6.3 Test de restauration
bash
# Pourquoi : Tester que la restauration fonctionne correctement
titou@firewall:~/backup-scripts$ ./restore-tool.sh restore web 2025-12-05_10-16-10 hostname.txt /tmp/test.txt
[INFO] Restauration: web/2025-12-05_10-16-10hostname.txt → /tmp/test.txt
[INFO] Chemin source: /backup/web/2025-12-05_10-16-10/hostname.txt
hostname.txt                           100%   12     2.4KB/s   00:00
[SUCCÈS] Fichier restauré: /tmp/test.txt
  Taille: 4,0K
  Permissions: -rw-rw-r-- titou titou

titou@firewall:~/backup-scripts$ cat /tmp/test.txt
serveur-web
7. TEST DE SUPPRESSION ACCIDENTELLE ET RESTAURATION
Objectif : Simuler un scénario réel de perte de données et démontrer la restauration.

bash
# Pourquoi : Créer un fichier dans /var/www/html/ qui sera sauvegardé par le script
titou@firewall:~$ ssh -i ~/.ssh/infra_key titou@192.168.100.50 "sudo mkdir -p /var/www/html/backup-test/; echo 'FICHIER CRITIQUE' | sudo tee /var/www/html/backup-test/fichier-critique.txt > /dev/null; sudo cat /var/www/html/backup-test/fichier-critique.txt"
FICHIER CRITIQUE

# Pourquoi : Capturer le fichier dans une sauvegarde
titou@firewall:~$ cd /home/titou/backup-scripts && ./backup-serverweb-from-firewall.sh
[2025-12-05 10:16:10] ✅ Début sauvegarde serverweb (depuis firewall)
[2025-12-05 10:16:15] ✅ Sauvegarde serverweb terminée

# Pourquoi : Simuler une erreur humaine (suppression accidentelle)
titou@firewall:~$ ssh -i ~/.ssh/infra_key titou@192.168.100.50 "sudo rm /var/www/html/backup-test/fichier-critique.txt; ls -la /var/www/html/backup-test/ 2>/dev/null || echo 'Dossier vide'"
total 8
drwxr-xr-x 2 root root 4096 déc.   5 10:16 .
drwxr-xr-x 3 root root 4096 déc.   5 10:15 ..

# Pourquoi : Télécharger l'archive contenant le fichier supprimé
titou@firewall:~$ scp -i ~/.ssh/infra_key titou@192.168.100.70:/backup/web/latest/www-html.tar.gz /tmp/
www-html.tar.gz                        100% 1423   264.3KB/s   00:00

# Pourquoi : Extraire l'archive et vérifier que le fichier est présent
titou@firewall:~$ mkdir -p /tmp/restore-test && tar -xzf /tmp/www-html.tar.gz -C /tmp/restore-test
titou@firewall:~$ sudo cat /tmp/restore-test/html/backup-test/fichier-critique.txt

# Pourquoi : Copier le fichier restauré sur serverweb
titou@firewall:~$ scp -i ~/.ssh/infra_key /tmp/restore-test/html/backup-test/fichier-critique.txt titou@192.168.100.50:/tmp/
fichier-critique.txt                   100%  333   102.6KB/s   00:00

# Pourquoi : Rétablir le fichier à son emplacement original
titou@firewall:~$ ssh -i ~/.ssh/infra_key titou@192.168.100.50 "sudo cp /tmp/fichier-critique.txt /var/www/html/backup-test/fichier-critique.txt; ls -la /var/www/html/backup-test/fichier-critique.txt"
-rw-r--r-- 1 root root 333 déc.   5 10:16 /var/www/html/backup-test/fichier-critique.txt
8. ÉTAT FINAL DU SYSTÈME
8.1 Statistiques Backup Server
bash
# Pourquoi : Vérifier l'espace disque disponible sur le backup server
titou@firewall:~$ ssh -i ~/.ssh/infra_key titou@192.168.100.70 "df -h / | grep /dev/"
/dev/mapper/ubuntu--vg-ubuntu--lv   14G  4,6G  8,5G  35% /

# Pourquoi : Afficher un récapitulatif de toutes les sauvegardes
titou@firewall:~$ ssh -i ~/.ssh/infra_key titou@192.168.100.70 "
    for dir in firewall web admin; do
        count=\$(find /backup/\$dir -maxdepth 1 -type d -name '2*' | wc -l)
        latest=\$(basename \$(readlink -f /backup/\$dir/latest) 2>/dev/null || echo 'Aucune')
        size=\$(du -sh /backup/\$dir 2>/dev/null | cut -f1)
        echo \"\$dir: \$count sauvegardes, dernière: \$latest, taille: \$size\"
    done
"
firewall: 3 sauvegardes, dernière: 2025-12-05_09-32-28, taille: 872K
web: 3 sauvegardes, dernière: 2025-12-05_10-13-11, taille: 3,6M
admin: 3 sauvegardes, dernière: 2025-12-05_09-45-37, taille: 1,2M

1. Installation de Bind9
bash
# Pourquoi : Mettre à jour les paquets et installer Bind9
titou@firewall:~$ sudo apt update
Hit:1 http://fr.archive.ubuntu.com/ubuntu noble InRelease
Get:2 http://fr.archive.ubuntu.com/ubuntu noble-updates InRelease [129 kB]
[...]
Fetched 8,122 kB in 2s (3,840 kB/s)
Reading package lists... Done

titou@firewall:~$ sudo apt install -y bind9 bind9utils bind9-doc
Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
The following additional packages will be installed:
  bind9-dnsutils bind9-host dns-root-data libbind9-192 libdns-export1920
  libisc-export1950 libisccc1920 libisccfg1920 libuv1 libxml2
Suggested packages:
  bind9-doc
The following NEW packages will be installed:
  bind9 bind9-dnsutils bind9-doc bind9-host bind9utils dns-root-data
  libbind9-192 libdns-export1920 libisc-export1950 libisccc1920
  libisccfg1920 libuv1 libxml2
0 upgraded, 13 newly installed, 0 to remove, 0 not upgraded.
Need to get 4,256 kB of archives.
After this operation, 9,184 kB of additional disk space will be used.
[...]
Setting up bind9 (1:9.18.24-1ubuntu2) ...
Created symlink /etc/systemd/system/multi-user.target.wants/named.service → /usr/lib/systemd/system/named.service.
Processing triggers for man-db (2.12.0-3build1) ...
Processing triggers for libc-bin (2.39-0ubuntu8.2) ...
2. Configuration de la zone maître
bash
# Pourquoi : Créer la configuration de la zone forward
titou@firewall:~$ sudo nano /etc/bind/named.conf.local
# Contenu ajouté :
zone "infra.local" {
    type master;
    file "/etc/bind/db.infra.local";
    allow-transfer { 192.168.100.0/24; };
    allow-query { any; };
    notify yes;
};

zone "100.168.192.in-addr.arpa" {
    type master;
    file "/etc/bind/db.192.168.100.rev";
    allow-transfer { 192.168.100.0/24; };
    allow-query { any; };
    notify yes;
};
3. Création du fichier de zone forward
bash
# Pourquoi : Définir tous les enregistrements DNS pour notre réseau
titou@firewall:~$ sudo nano /etc/bind/db.infra.local
# Contenu créé :
$TTL    604800
@       IN      SOA     firewall.infra.local. admin.infra.local. (
                          2025121001     ; Serial
                          604800         ; Refresh
                          86400          ; Retry
                          2419200        ; Expire
                          604800 )       ; Negative Cache TTL

; Serveurs de noms
@       IN      NS      firewall.infra.local.
@       IN      NS      serverweb.infra.local.

; Serveurs principaux
firewall        IN      A       192.168.100.1
serverweb       IN      A       192.168.100.50
adminserver     IN      A       192.168.100.60
backup          IN      A       192.168.100.70

; Alias et services
www             IN      CNAME   serverweb
web             IN      CNAME   serverweb
admin           IN      CNAME   adminserver
ns1             IN      CNAME   firewall
ns2             IN      CNAME   serverweb
files           IN      CNAME   serverweb

; Enregistrements TXT
@       IN      TXT     "Infrastructure reseau - Projet sauvegarde"
@       IN      TXT     "DNS gere par firewall (192.168.100.1)"

; MX pour mail (exemple)
@       IN      MX      10      serverweb.infra.local.
4. Création du fichier de zone reverse
bash
# Pourquoi : Permettre la résolution inverse (IP → nom)
titou@firewall:~$ sudo nano /etc/bind/db.192.168.100.rev
# Contenu créé :
$TTL    604800
@       IN      SOA     firewall.infra.local. admin.infra.local. (
                          2025121001     ; Serial
                          604800         ; Refresh
                          86400          ; Retry
                          2419200        ; Expire
                          604800 )       ; Negative Cache TTL

; Serveurs de noms
@       IN      NS      firewall.infra.local.
@       IN      NS      serverweb.infra.local.

; PTR Records
1       IN      PTR     firewall.infra.local.
50      IN      PTR     serverweb.infra.local.
60      IN      PTR     adminserver.infra.local.
70      IN      PTR     backup.infra.local.
5. Configuration des options Bind9
bash
# Pourquoi : Définir le comportement général du serveur DNS
titou@firewall:~$ sudo nano /etc/bind/named.conf.options
# Contenu modifié :
options {
    directory "/var/cache/bind";

    // Écoute sur toutes les interfaces
    listen-on { any; };
    listen-on-v6 { any; };

    // Autoriser les requêtes depuis notre réseau
    allow-query { localhost; 192.168.100.0/24; };

    // Autoriser la récursion pour notre réseau
    recursion yes;
    allow-recursion { localhost; 192.168.100.0/24; };

    // Forwarders vers DNS publics
    forwarders {
        8.8.8.8;
        1.1.1.1;
    };
    forward only;

    // DNSSEC
    dnssec-validation auto;

    // Autres options
    auth-nxdomain no;    # conform to RFC1035
    listen-on-v6 { any; };
};
6. Configuration du résolveur local
bash
# Pourquoi : Faire en sorte que le firewall utilise son propre DNS
titou@firewall:~$ sudo nano /etc/resolv.conf
# Contenu ajouté (en haut du fichier) :
nameserver 127.0.0.1
nameserver 192.168.100.1
search infra.local

# Pourquoi : Empêcher NetworkManager de modifier resolv.conf
titou@firewall:~$ sudo nano /etc/NetworkManager/NetworkManager.conf
# Ajout dans [main] :
dns=none

titou@firewall:~$ sudo systemctl restart NetworkManager
🔧 VÉRIFICATIONS ET TESTS
7. Vérification de la syntaxe
bash
# Pourquoi : Vérifier qu'il n'y a pas d'erreur de syntaxe
titou@firewall:~$ sudo named-checkconf
(rien retourné = succès)

titou@firewall:~$ sudo named-checkzone infra.local /etc/bind/db.infra.local
zone infra.local/IN: loaded serial 2025121001
OK

titou@firewall:~$ sudo named-checkzone 100.168.192.in-addr.arpa /etc/bind/db.192.168.100.rev
zone 100.168.192.in-addr.arpa/IN: loaded serial 2025121001
OK
8. Démarrage et activation du service
bash
# Pourquoi : Démarrer le service DNS et le configurer pour démarrer au boot
titou@firewall:~$ sudo systemctl restart bind9
titou@firewall:~$ sudo systemctl enable bind9
Synchronizing state of bind9.service with SysV service script with /lib/systemd/systemd-sysv-install.
Executing: /lib/systemd/systemd-sysv-install enable bind9

# Pourquoi : Vérifier que le service écoute sur le port 53
titou@firewall:~$ sudo netstat -tulpn | grep :53
tcp        0      0 192.168.100.1:53       0.0.0.0:*               LISTEN      7854/named
tcp        0      0 127.0.0.1:53           0.0.0.0:*               LISTEN      7854/named
tcp6       0      0 ::1:53                 :::*                    LISTEN      7854/named
udp        0      0 192.168.100.1:53       0.0.0.0:*                           7854/named
udp        0      0 127.0.0.1:53           0.0.0.0:*                           7854/named
udp6       0      0 ::1:53                 :::*                                7854/named
9. Tests de résolution DNS
bash
# Pourquoi : Tester la résolution locale
titou@firewall:~$ dig @127.0.0.1 firewall.infra.local +short
192.168.100.1

titou@firewall:~$ dig @127.0.0.1 serverweb.infra.local +short
192.168.100.50

titou@firewall:~$ dig @127.0.0.1 www.infra.local +short
serverweb.infra.local.
192.168.100.50

# Pourquoi : Tester la résolution inverse
titou@firewall:~$ dig @127.0.0.1 -x 192.168.100.1 +short
firewall.infra.local.

titou@firewall:~$ dig @127.0.0.1 -x 192.168.100.50 +short
serverweb.infra.local.

# Pourquoi : Tester la résolution externe (via forwarders)
titou@firewall:~$ dig @127.0.0.1 google.com +short
142.250.179.78

# Pourquoi : Tester depuis un autre serveur
titou@firewall:~$ ssh -i ~/.ssh/infra_key titou@192.168.100.50 "dig @192.168.100.1 firewall.infra.local +short"
192.168.100.1
🔄 INTÉGRATION AVEC LE SYSTÈME DE SAUVEGARDE
10. Ajout de la sauvegarde DNS au script firewall
bash
# Pourquoi : Sauvegarder la configuration DNS avec les autres éléments critiques
titou@firewall:~$ nano /home/titou/backup-firewall.sh
# Ajout après la section SSH :

# Sauvegarde DNS
log "   - Configuration DNS (Bind9)"
sudo tar -czf "$TEMP_DIR/etc-bind.tar.gz" -C /etc bind/ 2>/dev/null
sudo cp /etc/resolv.conf "$TEMP_DIR/resolv.conf.backup" 2>/dev/null

# Pourquoi : Tester la sauvegarde DNS
titou@firewall:~$ /home/titou/backup-firewall.sh
[2025-12-10 16:45:32] ✅ Début sauvegarde firewall
[2025-12-10 16:45:33]    - Configuration DNS (Bind9)
[...]
[2025-12-10 16:45:38] ✅ Sauvegarde firewall terminée avec succès

# Pourquoi : Vérifier que le DNS est bien sauvegardé
titou@firewall:~$ ssh -i ~/.ssh/infra_key titou@192.168.100.70 "tar -tzf /backup/firewall/latest/etc-bind.tar.gz 2>/dev/null | head -10"
etc/bind/
etc/bind/db.infra.local
etc/bind/named.conf
etc/bind/named.conf.local
etc/bind/named.conf.options
etc/bind/db.192.168.100.rev
etc/bind/rndc.key
etc/bind/bind.keys
11. Création d'un script de test DNS
bash
# Pourquoi : Avoir un outil de diagnostic rapide pour le DNS
titou@firewall:~$ cat > /home/titou/test-dns.sh << 'EOF'
#!/bin/bash
echo "🔍 TEST SERVEUR DNS SUR FIREWALL"
echo "================================"

echo "1. Service Bind9 :"
sudo systemctl status bind9 --no-pager | grep -E '(Active|Status)'

echo ""
echo "2. Résolution directe :"
for host in firewall serverweb adminserver backup www; do
    echo -n "  $host.infra.local : "
    dig @127.0.0.1 $host.infra.local +short 2>/dev/null || echo "ÉCHEC"
done

echo ""
echo "3. Résolution inverse :"
for ip in 1 50 60 70; do
    echo -n "  192.168.100.$ip : "
    dig @127.0.0.1 -x 192.168.100.$ip +short 2>/dev/null || echo "ÉCHEC"
done

echo ""
echo "4. Test depuis les autres serveurs :"
for server in 192.168.100.50 192.168.100.60 192.168.100.70; do
    echo -n "  Depuis $server : "
    ssh -i ~/.ssh/infra_key titou@$server "dig @192.168.100.1 firewall.infra.local +short 2>/dev/null | head -1" 2>/dev/null || echo "Hors ligne"
done

echo ""
echo "5. Logs DNS :"
sudo tail -5 /var/log/syslog | grep -i named
EOF

titou@firewall:~$ chmod +x /home/titou/test-dns.sh
12. Test complet du DNS
bash
# Pourquoi : Vérifier que tout fonctionne correctement
titou@firewall:~$ ./home/titou/test-dns.sh
🔍 TEST SERVEUR DNS SUR FIREWALL
================================
1. Service Bind9 :
     Active: active (running) since Wed 2025-12-10 16:18:05 CET; 28min ago
     Status: "running"

2. Résolution directe :
  firewall.infra.local : 192.168.100.1
  serverweb.infra.local : 192.168.100.50
  adminserver.infra.local : 192.168.100.60
  backup.infra.local : 192.168.100.70
  www.infra.local : serverweb.infra.local.
192.168.100.50

3. Résolution inverse :
  192.168.100.1 : firewall.infra.local.
  192.168.100.50 : serverweb.infra.local.
  192.168.100.60 : adminserver.infra.local.
  192.168.100.70 : backup.infra.local.

4. Test depuis les autres serveurs :
  Depuis 192.168.100.50 : 192.168.100.1
  Depuis 192.168.100.60 : 192.168.100.1
  Depuis 192.168.100.70 : 192.168.100.1

5. Logs DNS :
2025-12-10T16:45:32.123456+01:00 firewall named[7854]: client @0x7f8c12345678 192.168.100.1#43210 (www.infra.local): query: www.infra.local IN A + (127.0.0.1)
📊 ÉTAT FINAL DE LA CONFIGURATION DNS
Fichiers de configuration créés :
text
/etc/bind/named.conf.local           # Zones DNS définies
/etc/bind/db.infra.local             # Zone forward (noms → IP)
/etc/bind/db.192.168.100.rev         # Zone reverse (IP → noms)
/etc/bind/named.conf.options         # Options générales Bind9
/etc/resolv.conf                     # Configuration résolveur local
Services en cours d'exécution :
bash
titou@firewall:~$ sudo systemctl status bind9 --no-pager --full
● bind9.service - BIND Domain Name Server
     Loaded: loaded (/usr/lib/systemd/system/bind9.service; enabled; preset: enabled)
     Active: active (running) since Wed 2025-12-10 16:18:05 CET; 30min ago
       Docs: man:named(8)
   Main PID: 7854 (named)
      Tasks: 5 (limit: 4652)
     Memory: 18.3M
        CPU: 123ms
     CGroup: /system.slice/bind9.service
             └─7854 /usr/sbin/named -f -u bind
Règles firewalld pour DNS :
bash
# Pourquoi : Vérifier que le port DNS est ouvert sur le firewall
titou@firewall:~$ sudo firewall-cmd --list-all --zone=internal
internal (active)
  target: ACCEPT
  interfaces: enp0s8
  services: dhcp dns ssh
  ports: 873/tcp
  forward: no
  masquerade: no
  forward-ports:
  source-ports:
  icmp-blocks:
  rich rules:

# Total: 9 sauvegardes (3 par serveur)
