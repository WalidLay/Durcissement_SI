#!/bin/sh # # Simple PareFeu #

#####################
##### # Zone IP6 ####
###################### 
# Désactivation d'ipv6 
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6 
echo 1 > /proc/sys/net/ipv6/conf/default/disable_ipv6 
echo 1 > /proc/sys/net/ipv6/conf/lo/disable_ipv6 
IPT6="/sbin/ip6tables" 
echo "Mise en place des règles du PareFeu IPV6" 
$IPT6 -F 
$IPT6 -X 
$IPT6 -t mangle -F 
$IPT6 -t mangle -X 
# Interdiction de tout IPV6 
$IPT6 -P INPUT DROP 
$IPT6 -P OUTPUT DROP 
$IPT6 -P FORWARD DROP 

#####################
##### # Zone IPV4 ####
###################### 
PATH=/bin:/sbin:/usr/bin:/usr/sbin 
# Ports du serveur accessibles depuis l'extérieur 
TCP_SERVICES="22 80 443" # SSH et Serveur WeB 
UDP_SERVICES="" 
# Ports cibles d'une communication émise par le serveur 
REMOTE_TCP_SERVICES="80 443 " # web browsing et gmail 
REMOTE_UDP_SERVICES="53" # DNS 

#########################################
# Mise en oeuvre des règles du Pare feu #
######################################## 
fw_start () { 
	#-------------------------------- 
	# Traffic entrant : 
	# On commence par tout bloquer 
	/sbin/iptables -P INPUT DROP 
	#####A VALIDER 
	# Rejet des demandes de connexions non conformes (FIN-URG-PUSH, XMAS, NullScan, SYN-RST et NEW not SYN) 
	iptables -A INPUT -p tcp --tcp-flags FIN,URG,PSH FIN,URG,PSH -j DROP 
	iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP 
	iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP 
	iptables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP 
	iptables -A INPUT -p tcp -m tcp ! --syn -m state --state NEW -j DROP 
	#####A VALIDER 
	# On rejette les trame en broadcast et en multicast sur EXTIF (évite leur journalisation) 
	#iptables -A INPUT -m addrtype --dst-type BROADCAST,MULTICAST -j DROP 
	#####A VALIDER 
	##LIMITER LE MODE BURST 
	iptables -A INPUT -p tcp --syn -m limit --limit 3/s -j ACCEPT 
	# puis on autorise les retours des connexions initiées depuis l'intérieur 
	/sbin/iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT 
	# ainsi que les connexions entrantes sur loopback 
	/sbin/iptables -A INPUT -i lo -j ACCEPT

       # préciser les ports autorisés 
       # Ouverture des ports
       if [ -n "$TCP_SERVICES" ] ; then for PORT in $TCP_SERVICES; do 
	       /sbin/iptables -A INPUT -p tcp -m state --state NEW --sport 1024:65535 --dport ${PORT} -j ACCEPT
	done 
       fi 
       if [ -n "$UDP_SERVICES" ] ; then for PORT in $UDP_SERVICES; do 
	       /sbin/iptables -A INPUT -p udp -m state --state NEW --sport 1024:65535 --dport ${PORT} -j ACCEPT 
       done 
       fi 
       # Les flux qui n'ont pas été autorisés auparavant sont loggués 
       # (avant d'être supprimés par la politique par défaut) 
       # a déplcer car l'autorisation est plus loin. si laissé ici log de tout les inputs. 
       /sbin/iptables -A INPUT -j LOG 
       #------------------------------- 
       # Traffic sortant 
       # On commence par tout bloquer 
       /sbin/iptables -P OUTPUT DROP 
       # puis on autorise les retours des connexions (autorisées) et initiées depuis l'extérieur 
       /sbin/iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT 
       # ainsi que les connexions sortantes sur loopback 
       /sbin/iptables -A OUTPUT -o lo -j ACCEPT 
       # préciser les ports autorisés 
       # Ouverture des ports 
       if [ -n "$REMOTE_TCP_SERVICES" ] ; then for PORT in $REMOTE_TCP_SERVICES; do 
	       /sbin/iptables -A OUTPUT -p tcp -m state --state NEW --sport 1024:65535 --dport ${PORT} -j ACCEPT 
       done
       fi 
       if [ -n "$REMOTE_UDP_SERVICES" ] ; then for PORT in $REMOTE_UDP_SERVICES; do 
	       /sbin/iptables -A OUTPUT -p udp -m state --state NEW --sport 1024:65535 --dport ${PORT} -j ACCEPT 
       done 
       fi 
       # ICMP est explicitement interdit 
       
	/sbin/iptables -A INPUT -p icmp -j DROP 
	/sbin/iptables -A OUTPUT -p icmp -j DROP 
       # Les flux qui n'ont pas été autorisés auparavant sont loggués 
       # (avant d'être supprimés par la politique par défaut) 
       /sbin/iptables -A OUTPUT -j LOG 
       # Autres protections réseau 
       # (certaines valeurs ne fonctionnent que sur certains  noyaux) 
       echo 1 > /proc/sys/net/ipv4/tcp_syncookies 
       echo 0 > /proc/sys/net/ipv4/ip_forward 
       echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts 
       echo 1 > /proc/sys/net/ipv4/conf/all/log_martians
       echo 1 > /proc/sys/net/ipv4/icmp_ignore_bogus_error_responses 
       echo 1 > /proc/sys/net/ipv4/conf/all/rp_filter 
       echo 0 > /proc/sys/net/ipv4/conf/all/send_redirects 
       echo 0 > /proc/sys/net/ipv4/conf/all/accept_source_route
	}
########################## 
### Arret du PareFeu #####
########################## 
fw_stop () { 

	/sbin/iptables -F 
	/sbin/iptables -t nat -F 
	/sbin/iptables -t mangle -F 
	/sbin/iptables -P INPUT DROP 
	/sbin/iptables -P FORWARD DROP 
	/sbin/iptables -P OUTPUT DROP 
	} 

##################################
#### # Parefeu en mode laxist ####
################################## 
fw_clear () { 
	/sbin/iptables -F 
	/sbin/iptables -t nat -F 
	/sbin/iptables -t mangle -F 
	/sbin/iptables -P INPUT ACCEPT 
	/sbin/iptables -P FORWARD ACCEPT 
	/sbin/iptables -P OUTPUT ACCEPT 
	} 
##################################
### # Redemarrage du PareFeu #####
################################## 
fw_restart () { 
	fw_stop 
	fw_start 
	} 

#########################################################################################
##### # Sauvegarde, mise en place 30 secondes et remise en place de la sauvegarde. ######
######################################################################################### 
fw_save () { 
	/sbin/iptables-save > /etc/iptables.backup 
	} 
fw_restore () { 
	if [ -e /etc/iptables.backup ]; then 
	/sbin/iptables-restore < /etc/iptables.backup 
	fi 
	} 
fw_test () { 
	fw_save
       	fw_restart sleep 30 
	fw_restore 
	} 
	
case "$1" in 
start|restart) 
echo -n "Mise en place des règles du PareFeu IPV4 " 
fw_restart 
echo " Fait." 
;; 
stop) 
echo -n "PareFeu en mode bloquant" 
fw_stop 
echo " Fait." 
;; 
open) 
echo -n "PareFeu en mode ouvert" 
fw_clear 
echo " Fait." 
;; 
test) 
echo -n "Test de règles de PareFeu" 
echo -n "La configuration précédente sera restaurée dans 30 secondes." 
fw_test echo -n "La configuration précédente a été remise en place" 
;;
*) 
echo "Usage: $0 {start|stop|restart|open|test}" 
echo "Soyez conscients que l'option stop interdit tout flux entrant ou sortant (serveur = caillou) !!!" 
exit 1 
;; 
esac 
exit 0
