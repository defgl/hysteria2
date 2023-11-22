#!/bin/bash

export LANG=en_US.UTF-8

RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
PLAIN="\033[0m"

red(){
    echo -e "\033[31m\033[01m$1\033[0m"
}

green(){
    echo -e "\033[32m\033[01m$1\033[0m"
}

yellow(){
    echo -e "\033[33m\033[01m$1\033[0m"
}

# Check for root privileges
[[ $EUID -ne 0 ]] && red "PLEASE RUN AS ROOT" && exit 1

# Simplify OS detection
OS_NAME=$(grep -Eo "(debian|ubuntu|centos|fedora|red hat|oracle linux|alma|rocky|amazon linux)" /etc/os-release | tr '[:upper:]' '[:lower:]' | head -n 1)

# Define package management commands based on OS
case "$OS_NAME" in
    debian|ubuntu)
        PACKAGE_MANAGER_UPDATE="apt-get update"
        PACKAGE_MANAGER_INSTALL="apt-get install -y"
        ;;
    centos|red\ hat|oracle\ linux|alma|rocky)
        PACKAGE_MANAGER_UPDATE="yum update -y"
        PACKAGE_MANAGER_INSTALL="yum install -y"
        ;;
    fedora)
        PACKAGE_MANAGER_UPDATE="dnf update -y"
        PACKAGE_MANAGER_INSTALL="dnf install -y"
        ;;
    *)
        red "UNSUPPORTED OS"
        exit 1
        ;;
esac

# Update and install required packages
$PACKAGE_MANAGER_UPDATE
$PACKAGE_MANAGER_INSTALL curl wget sudo qrencode procps iptables-persistent netfilter-persistent

# Additional logic if needed...

realip(){
    ip=$(curl -s4m8 ip.sb -k) || ip=$(curl -s6m8 ip.sb -k)
}

inst_cert(){
    green "SELECT CERTIFICATE APPLICATION METHOD:"
    echo ""
    echo -e " ${GREEN}1.${PLAIN} SELF-SIGNED CERTIFICATE (BING) ${YELLOW}(DEFAULT)${PLAIN}"
    echo -e " ${GREEN}2.${PLAIN} AUTOMATIC ACME SCRIPT APPLICATION"
    echo -e " ${GREEN}3.${PLAIN} CUSTOM CERTIFICATE PATH"
    echo ""
    read -rp "OPTION [1-3]: " certInput
    if [[ $certInput == 2 ]]; then
        cert_path="/root/cert.crt"
        key_path="/root/private.key"

        chmod -R 777 /root # 让 Hysteria 主程序访问到 /root 目录

        if [[ -f /root/cert.crt && -f /root/private.key ]] && [[ -s /root/cert.crt && -s /root/private.key ]] && [[ -f /root/ca.log ]]; then
            domain=$(cat /root/ca.log)
            green "EXISTING CERTIFICATE DETECTED FOR DOMAIN: $domain, APPLYING"
            hy_domain=$domain
        else
            WARPv4Status=$(curl -s4m8 https://www.cloudflare.com/cdn-cgi/trace -k | grep warp | cut -d= -f2)
            WARPv6Status=$(curl -s6m8 https://www.cloudflare.com/cdn-cgi/trace -k | grep warp | cut -d= -f2)
            if [[ $WARPv4Status =~ on|plus ]] || [[ $WARPv6Status =~ on|plus ]]; then
                wg-quick down wgcf >/dev/null 2>&1
                systemctl stop warp-go >/dev/null 2>&1
                realip
                wg-quick up wgcf >/dev/null 2>&1
                systemctl start warp-go >/dev/null 2>&1
            else
                realip
            fi
            
            read -p "DOMAIN FOR APPLYING CERTIFICATE:" domain
            [[ -z $domain ]] && red "INVALID INPUT, EXITING SCRIPT" && exit 1
            green "CONFIRMED:$domain" && sleep 1
            domainIP=$(curl -sm8 ipget.net/?ip="${domain}")
            if [[ $domainIP == $ip ]]; then
                ${PACKAGE_INSTALL[int]} curl wget sudo socat openssl
                if [[ $SYSTEM == "CentOS" ]]; then
                    ${PACKAGE_INSTALL[int]} cronie
                    systemctl start crond
                    systemctl enable crond
                else
                    ${PACKAGE_INSTALL[int]} cron
                    systemctl start cron
                    systemctl enable cron
                fi
                curl https://get.acme.sh | sh -s email=$(date +%s%N | md5sum | cut -c 1-16)@gmail.com
                source ~/.bashrc
                bash ~/.acme.sh/acme.sh --upgrade --auto-upgrade
                bash ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt
                if [[ -n $(echo $ip | grep ":") ]]; then
                    bash ~/.acme.sh/acme.sh --issue -d ${domain} --standalone -k ec-256 --listen-v6 --insecure
                else
                    bash ~/.acme.sh/acme.sh --issue -d ${domain} --standalone -k ec-256 --insecure
                fi
                bash ~/.acme.sh/acme.sh --install-cert -d ${domain} --key-file /root/private.key --fullchain-file /root/cert.crt --ecc
                if [[ -f /root/cert.crt && -f /root/private.key ]] && [[ -s /root/cert.crt && -s /root/private.key ]]; then
                    echo $domain > /root/ca.log
                    sed -i '/--cron/d' /etc/crontab >/dev/null 2>&1
                    echo "0 0 * * * root bash /root/.acme.sh/acme.sh --cron -f >/dev/null 2>&1" >> /etc/crontab
                    green "CERTIFICATE APPLICATION SUCCESSFUL! CERTIFICATE (cert.crt) AND PRIVATE KEY (private.key) SAVED TO /root DIRECTORY"
                    yellow "CERTIFICATE CRT FILE PATH: /root/cert.crt"
                    yellow "PRIVATE KEY FILE PATH: /root/private.key"
                    hy_domain=$domain
                fi

            else
                red "DOMAIN NAME PROVIDED CANNOT BE RESOLVED"
                exit 1
            fi
        fi
    elif [[ $certInput == 3 ]]; then
        read -p "ENTER PATH TO PUBLIC KEY FILE (CRT): " cert_path
        yellow "PUBLIC KEY FILE (CRT) PATH: $certpath "
        read -p "ENTER PATH TO PRIVATE KEY FILE (KEY): " key_path
        yellow "PRIVATE KEY FILE (KEY) PATH: $keypath "
        read -p "ENTER CERTIFICATE DOMAIN: " domain
        yellow "CERTIFICATE DOMAIN: $domain"    
        hy_domain=$domain
    else
        green "USING SELF-SIGNED CERTIFICATE (FROM BING)"

        cert_path="/etc/hysteria/cert.crt"
        key_path="/etc/hysteria/private.key"
        openssl ecparam -genkey -name prime256v1 -out /etc/hysteria/private.key
        openssl req -new -x509 -days 36500 -key /etc/hysteria/private.key -out /etc/hysteria/cert.crt -subj "/CN=www.bing.com"
        chmod 777 /etc/hysteria/cert.crt
        chmod 777 /etc/hysteria/private.key
        hy_domain="www.bing.com"
        domain="www.bing.com"
    fi
}

inst_port(){
    iptables -t nat -F PREROUTING >/dev/null 2>&1

    read -p "SET HYSTERIA 2 PORT [1-65535] (DEFAULT FOR RANDOM): " port
    [[ -z $port ]] && port=$(shuf -i 2000-65535 -n 1)
    until [[ -z $(ss -tunlp | grep -w udp | awk '{print $5}' | sed 's/.*://g' | grep -w "$port") ]]; do
        if [[ -n $(ss -tunlp | grep -w udp | awk '{print $5}' | sed 's/.*://g' | grep -w "$port") ]]; then
            echo -e "${RED} PORT $port ${PLAIN} IS ALREADY IN USED. PLEASE RETRY A DIFFERENT PORT"
            read -p "SET HYSTERIA 2 PORT [1-65535] (DEFAULT FOR RANDOM): " port
            [[ -z $port ]] && port=$(shuf -i 2000-65535 -n 1)
        fi
    done


    yellow "PORT CONFIRMED:$port"
    inst_jump
}

inst_jump(){
    green "HYSTERIA 2 PORT USAGE MODE:"
    echo ""
    echo -e " ${GREEN}1.${PLAIN} SINGLE-PORT ${YELLOW}(DEFAULT)${PLAIN}"
    echo -e " ${GREEN}2.${PLAIN} PORT HOPPING"
    echo ""
    read -rp "OPTION [1-2]: " jumpInput
    if [[ $jumpInput == 2 ]]; then
        read -p "SET START port FOR RANGE (RECOMMENDED 10000-65535): " firstport
        read -p "SET END PORT FOR RANGE (MUST BE GREATER THAN LAST INPUT): " endport
        if [[ $firstport -ge $endport ]]; then
            until [[ $firstport -le $endport ]]; do
                if [[ $firstport -ge $endport ]]; then
                    red "START PORT MUST BE LESS THAN END PORT. PLEASE RE-ENTER START AND END PORTS."
                    read -p "SET START PORT FOR RANGE (RECOMMENDED BETWEEN 10000-65535): " firstport
                    read -p "SET END PORT FOR RANGE (RECOMMENDED BETWEEN 10000-65535, must be greater than start port): " endport

                fi
            done
        fi
        iptables -t nat -A PREROUTING -p udp --dport $firstport:$endport  -j DNAT --to-destination :$port
        ip6tables -t nat -A PREROUTING -p udp --dport $firstport:$endport  -j DNAT --to-destination :$port
        netfilter-persistent save >/dev/null 2>&1
    else
        red "CONTINUING IN SINGLE PORT MODE"
    fi
}

inst_pwd() {
    read -p "Set PASSWORD (PRESS ENTER FOR RANDOM): " auth_pwd
    [[ -z $auth_pwd ]] && auth_pwd=$(date +%s%N | md5sum | cut -c 1-8)
    yellow "CONFIRMED: $auth_pwd"
}


inst_site() {
    read -rp "ENTER MASQUERADE SITE URL (OMIT https://) [DEFAULT FOR SEGA MAIMAI SITE]: " proxysite
    [[ -z $proxysite ]] && proxysite="maimai.sega.jp"
    yellow "CONFIRMED: $proxysite"
}


insthysteria(){
    warpv6=$(curl -s6m8 https://www.cloudflare.com/cdn-cgi/trace -k | grep warp | cut -d= -f2)
    warpv4=$(curl -s4m8 https://www.cloudflare.com/cdn-cgi/trace -k | grep warp | cut -d= -f2)
    if [[ $warpv4 =~ on|plus || $warpv6 =~ on|plus ]]; then
        wg-quick down wgcf >/dev/null 2>&1
        systemctl stop warp-go >/dev/null 2>&1
        realip
        systemctl start warp-go >/dev/null 2>&1
        wg-quick up wgcf >/dev/null 2>&1
    else
        realip
    fi

    if [[ ! ${SYSTEM} == "CentOS" ]]; then
        ${PACKAGE_UPDATE}
    fi
    ${PACKAGE_INSTALL} curl wget sudo qrencode procps iptables-persistent netfilter-persistent

    # Install Hysteria 2
    bash <(curl -fsSL https://get.hy2.sh/)

    if [[ -f "/usr/local/bin/hysteria" ]]; then
        green "INSTALLED SUCCESSFULLY!"
    else
        red "INSTALLED FAILED!"
        exit 1
    fi

    # 询问用户 Hysteria 配置
    inst_cert
    inst_port
    inst_pwd
    inst_site

    # 设置 Hysteria 配置文件
    cat << EOF > /etc/hysteria/config.yaml
listen: :$port

tls:
  cert: $cert_path
  key: $key_path

quic:
  initStreamReceiveWindow: 16777216
  maxStreamReceiveWindow: 16777216
  initConnReceiveWindow: 33554432
  maxConnReceiveWindow: 33554432

auth:
  type: password
  password: $auth_pwd

masquerade:
  type: proxy
  proxy:
    url: https://$proxysite
    rewriteHost: true
EOF

    # 确定最终入站端口范围
    if [[ -n $firstport ]]; then
        last_port="$port,$firstport-$endport"
    else
        last_port=$port
    fi

    # 给 IPv6 地址加中括号
    if [[ -n $(echo $ip | grep ":") ]]; then
        last_ip="[$ip]"
    else
        last_ip=$ip
    fi

    mkdir /root/hy

    url="hysteria2://$auth_pwd@$last_ip:$last_port/?insecure=1&sni=$hy_domain"
    echo $url > /root/hy/url.txt
    nohopurl="hysteria2://$auth_pwd@$last_ip:$port/?insecure=1&sni=$hy_domain"
    echo $nohopurl > /root/hy/url-nohop.txt
    surge_format="TEST HY2 = hysteria2, $last_ip, $last_port, password=$auth_pwd, sni=$hy_domain, download-bandwidth=1000"
    echo $surge_format > /root/hy/HY4SURGE.txt

    systemctl daemon-reload
    systemctl enable hysteria-server
    systemctl start hysteria-server
    if [[ -n $(systemctl status hysteria-server 2>/dev/null | grep -w active) && -f '/etc/hysteria/config.yaml' ]]; then
        green "HYSTERIA 2 STARTED SUCCESSFULLY"
    else
        red "HYSTERIA 2 SERVICE FAILED TO START. RUN 'systemctl status hysteria-server' FOR STATUS. EXITING SCRIPT." && exit 1
    fi
    red "私はあなたに別れを告げる旅に出た。"
    green "HYSTERIA 2 PROXY SERVICE INSTALLED SUCCESSFULLY"
    yellow "HYSTERIA 2 NODE SHARE LINK (PATH: /root/hy/url.txt):"
    red "$(cat /root/hy/url.txt)"
    yellow "HYSTERIA 2 NODE SINGLE PORT SHARE LINK (PATH: /root/hy/url-nohop.txt):"
    red "$(cat /root/hy/url-nohop.txt)"
    yellow "HYSTERIA 2 NODE INFO FOR SURGE (PATH: /root/hy/HY4SURGE.txt):"
    red "$(cat /root/hy/HY4SURGE.txt)"
}

unsthysteria(){
    systemctl stop hysteria-server.service >/dev/null 2>&1
    systemctl disable hysteria-server.service >/dev/null 2>&1
    rm -f /lib/systemd/system/hysteria-server.service /lib/systemd/system/hysteria-server@.service
    rm -rf /usr/local/bin/hysteria /etc/hysteria /root/hy /root/hysteria.sh
    iptables -t nat -F PREROUTING >/dev/null 2>&1
    netfilter-persistent save >/dev/null 2>&1

    green "UNINSTALLED SCUEESSFULLY"
}

starthysteria(){
    systemctl start hysteria-server
    systemctl enable hysteria-server >/dev/null 2>&1
}

stophysteria(){
    systemctl stop hysteria-server
    systemctl disable hysteria-server >/dev/null 2>&1
}

hysteriaswitch(){
    yellow "鳴神の少し響みて さし曇り"
    yellow "雨も降らぬか 君を留めむ"
    echo ""
    echo -e " ${GREEN}1.${PLAIN} START"
    echo -e " ${GREEN}2.${PLAIN} SHUTDOWN"
    echo -e " ${GREEN}3.${PLAIN} REBOOT"
    echo ""
    read -rp "OPTION [0-3]: " switchInput
    case $switchInput in
        1 ) starthysteria ;;
        2 ) stophysteria ;;
        3 ) stophysteria && starthysteria ;;
        * ) exit 1 ;;
    esac
}

changeport(){
    oldport=$(cat /etc/hysteria/config.yaml 2>/dev/null | sed -n 1p | awk '{print $2}' | awk -F ":" '{print $2}')
    
    read -p "ENTER HYSTERIA 2 PORT [1-65535] (PRESS ENTER FOR RANDOM PORT): " port
    [[ -z $port ]] && port=$(shuf -i 2000-65535 -n 1)

    until [[ -z $(ss -tunlp | grep -w udp | awk '{print $5}' | sed 's/.*://g' | grep -w "$port") ]]; do
        if [[ -n $(ss -tunlp | grep -w udp | awk '{print $5}' | sed 's/.*://g' | grep -w "$port") ]]; then
            echo -e "${RED} PORT $port ${PLAIN} IS ALREADY IN USE BY ANOTHER APPLICATION. PLEASE CHOOSE A DIFFERENT PORT!"
            read -p "SET HYSTERIA 2 PORT [1-65535] (PRESS ENTER FOR RANDOM PORT): " port
            [[ -z $port ]] && port=$(shuf -i 2000-65535 -n 1)
        fi
    done

    sed -i "1s#$oldport#$port#g" /etc/hysteria/config.yaml
    sed -i "1s#$oldport#$port#g" /root/hy/HY4SURGE.txt

    stophysteria && starthysteria

    green "PORT UPDATED: $port"
    yellow "PLEASE MANUALLY UPDATE THE CLIENT CONFIGURATION FILE TO USE THE NODE"
    showconf
}

changepasswd(){
    oldpasswd=$(cat /etc/hysteria/config.yaml 2>/dev/null | sed -n 15p | awk '{print $2}')

    read -p "ENTER HYSTERIA 2 PASSWORD (PRESS ENTER FOR RANDOM): " passwd
    [[ -z $passwd ]] && passwd=$(date +%s%N | md5sum | cut -c 1-8)

    sed -i "1s#$oldpasswd#$passwd#g" /etc/hysteria/config.yaml
    sed -i "1s#$oldpasswd#$passwd#g" /root/hy/HY4SURGE.txt

    stophysteria && starthysteria

    green "PASSWORD UPDATED: $auth_pwd"
    yellow "PLEASE MANUALLY UPDATE THE CLIENT CONFIGURATION FILE TO USE THE NODE"
    showconf
}

change_cert(){
    old_cert=$(cat /etc/hysteria/config.yaml | grep cert | awk -F " " '{print $2}')
    old_key=$(cat /etc/hysteria/config.yaml | grep key | awk -F " " '{print $2}')
    old_hydomain=$(cat /root/hy/HY4SURGE.txt | grep sni | awk '{print $2}')

    inst_cert

    sed -i "s!$old_cert!$cert_path!g" /etc/hysteria/config.yaml
    sed -i "s!$old_key!$key_path!g" /etc/hysteria/config.yaml
    sed -i "6s/$old_hydomain/$hy_domain/g" /root/hy/HY4SURGE.txt

    stophysteria && starthysteria

    green "HYSTERIA 2 NODE CERTIFICATE TYPE SUCCESSFULLY CHANGED"
    yellow "PLEASE MANUALLY UPDATE CLIENT CONFIGURATION FILE TO USE NODE"
    showconf
}

changeproxysite(){
    oldproxysite=$(cat /etc/hysteria/config.yaml | grep url | awk -F " " '{print $2}' | awk -F "https://" '{print $2}')
    
    inst_site

    sed -i "s#$oldproxysite#$proxysite#g" /etc/caddy/Caddyfile

    stophysteria && starthysteria

    green "HYSTERIA 2 NODE PROXY SITE SUCCESSFULLY CHANGED TO: $proxysite"
}

changeconf(){
    green "HYSTERIA 2 CONFIGURATION OPTIONS:"
    echo -e " ${GREEN}1.${PLAIN} CHANGE PORT"
    echo -e " ${GREEN}2.${PLAIN} CHANGE PASSWORD"
    echo -e " ${GREEN}3.${PLAIN} CHANGE CERTIFICATE"
    echo -e " ${GREEN}4.${PLAIN} CHANGE PROXY SITE"
    echo ""
    read -p " PLEASE SELECT AN OPTION [1-4]: " confAnswer
    case $confAnswer in
        1 ) changeport ;;
        2 ) changepasswd ;;
        3 ) change_cert ;;
        4 ) changeproxysite ;;
        * ) exit 1 ;;
    esac
}

showconf(){
    yellow "HYSTERIA 2 NODE SHARE LINK:"
    red "$(cat /root/hy/url.txt)"
    yellow "HYSTERIA 2 NODE SINGLE PORT SHARE LINK:"
    red "$(cat /root/hy/url-nohop.txt)"
    yellow "HYSTERIA 2 NODE INFO FOR SURGE:"
    red "$(cat /root/hy/HY4SURGE.txt)"
}

update_core(){
    # ReInstall Hysteria 2
    bash <(curl -fsSL https://get.hy2.sh/)
}

menu() {
    clear
    echo -e " ${LIGHT_RED}HYSTERIA 2${PLAIN}"
    echo ""
    echo -e " ${LIGHT_BLUE}AT WHAT SPEED MUST I LIVE, TO BE ABLE TO SEE YOU AGAIN?${PLAIN}"
    echo " -------------"
    echo -e " ${GREEN}1.${PLAIN} INSTALL"
    echo -e " ${GREEN}2.${PLAIN} ${RED}UNINSTALL${PLAIN}"
    echo " -------------"
    echo -e " ${GREEN}3.${PLAIN} STOP, START, RESTART"
    echo -e " ${GREEN}4.${PLAIN} MODIF CONFIG"
    echo -e " ${GREEN}5.${PLAIN} DISPLAY CONFIG"
    echo " -------------"
    echo -e " ${GREEN}6.${PLAIN} UPDATE CORE"
    echo " -------------"
    echo -e " ${GREEN}0.${PLAIN} EXIT"
    echo ""
    read -rp "PLEASE ENTER AN OPTION [0-5]: " menuInput
    case $menuInput in
        1 ) insthysteria ;;
        2 ) unsthysteria ;;
        3 ) hysteriaswitch ;;
        4 ) changeconf ;;
        5 ) showconf ;;
        6 ) update_core ;;
        0 ) exit 1 ;;
        * ) menu ;;
    esac
}

menu