1. CONNECTIVITÉ RÉSEAU
bash
# Ping de tous les serveurs
ping -c 1 192.168.100.50
ping -c 1 192.168.100.60
ping -c 1 192.168.100.70

# Test SSH vers un serveur
ssh -i ~/.ssh/infra_key titou@192.168.100.50 "hostname"
2. FIREWALL
bash
# Vérifier les zones actives
sudo firewall-cmd --get-active-zones

# Voir les règles NAT
sudo firewall-cmd --list-all --zone=external | grep forward-ports

# Voir l'IP du firewall
ip addr show enp0s8 | grep "inet "
3. DNS
bash
# Vérifier le service DNS
sudo systemctl status bind9 | grep "Active:"

# Résolution directe
dig @192.168.100.1 firewall.infra.local +short
dig @192.168.100.1 serverweb.infra.local +short
dig @192.168.100.1 www.infra.local +short

# Résolution inverse
dig @192.168.100.1 -x 192.168.100.1 +short
dig @192.168.100.1 -x 192.168.100.50 +short
4. SERVEUR WEB
bash
# Vérifier Nginx à distance
ssh -i ~/.ssh/infra_key titou@192.168.100.50 "sudo systemctl status nginx | head -3"

# Montrer la page web
ssh -i ~/.ssh/infra_key titou@192.168.100.50 "cat /var/www/html/index.html"

# Tester avec curl (depuis le firewall)
curl -I http://192.168.100.50

# Voir le code source
curl http://192.168.100.50 | head -20

5. SAUVEGARDE
bash
# Voir les sauvegardes sur le backup
ssh -i ~/.ssh/infra_key titou@192.168.100.70 "ls -la /backup/"

# Voir la dernière sauvegarde de chaque serveur
ssh -i ~/.ssh/infra_key titou@192.168.100.70 "ls -la /backup/*/latest"

# Lancer une sauvegarde manuelle
/home/titou/backup-firewall.sh

# Montrer le script
 cat /home/titou/backup-firewall.sh

# script total 
titou@firewall:~$ ssh -i ~/.ssh/infra_key titou@192.168.100.70 "ls -la /backup/*/latest"

6. AUTOMATISATION
bash
# Voir les tâches cron
crontab -l

# Voir les logs de sauvegarde
ls -la /home/titou/backup-logs/ | tail -3

9. SCÉNARIO CRASH/RESTAURATION
bash
# 1. Créer un fichier test
ssh -i ~/.ssh/infra_key titou@192.168.100.50 "echo 'TEST' | sudo tee /var/www/html/test.txt"

# 2. Sauvegarder
/home/titou/backup-scripts/backup-serverweb-from-firewall.sh

# 3. Supprimer
ssh -i ~/.ssh/infra_key titou@192.168.100.50 "sudo rm /var/www/html/test.txt"

# 4. Vérifier la sauvegarde
ssh -i ~/.ssh/infra_key titou@192.168.100.70 "tar -tzf /backup/web/latest/www-html.tar.gz | grep test.txt"

# Telecharger
scp -i ~/.ssh/infra_key titou@192.168.100.70:/backup/web/latest/www-html.tar.gz /tmp/restore.tar.gz

# Extraire le fichier 
tar -xzf /tmp/restore.tar.gz -C /tmp html/test.txt --strip-components=1

# Copier sur web
scp -i ~/.ssh/infra_key /tmp/test.txt titou@192.168.100.50:/tmp/

# Remmetre en place
ssh -i ~/.ssh/infra_key titou@192.168.100.50 "sudo cp /tmp/test.txt /var/www/html/test.txt"

# Test
ssh -i ~/.ssh/infra_key titou@192.168.100.50 "cat /var/www/html/test.txt"

10. VÉRIFICATION FINALE
bash
# Services en cours d'exécution
sudo systemctl is-active bind9 firewalld ssh

# DNS fonctionnel
dig @192.168.100.1 google.com

# Sauvegardes présentes
ssh -i ~/.ssh/infra_key titou@192.168.100.70 "du -sh /backup/"