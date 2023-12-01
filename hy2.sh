#!/bin/bash

export LANG=en_US.UTF-8

RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
PLAIN="\033[0m"
# 颜色定义
BLUE="\033[34m"
PURPLE="\033[35m"
CYAN="\033[36m"

# 相应的函数

red(){
    echo -e "\033[31m\033[01m$1\033[0m"
}

green(){
    echo -e "\033[32m\033[01m$1\033[0m"
}

yellow(){
    echo -e "\033[33m\033[01m$1\033[0m"
}

blue(){
    echo -e "${BLUE}\033[01m$1${PLAIN}"
}

purple(){
    echo -e "${PURPLE}\033[01m$1${PLAIN}"
}

cyan(){
    echo -e "${CYAN}\033[01m$1${PLAIN}"
}

# 判断系统及定义系统安装依赖方式
REGEX=("debian" "ubuntu" "centos|red hat|kernel|oracle linux|alma|rocky" "'amazon linux'" "fedora")
RELEASE=("Debian" "Ubuntu" "CentOS" "CentOS" "Fedora")
PACKAGE_UPDATE=("apt-get update" "apt-get update" "yum -y update" "yum -y update" "yum -y update")
PACKAGE_INSTALL=("apt -y install" "apt -y install" "yum -y install" "yum -y install" "yum -y install")
PACKAGE_REMOVE=("apt -y remove" "apt -y remove" "yum -y remove" "yum -y remove" "yum -y remove")
PACKAGE_UNINSTALL=("apt -y autoremove" "apt -y autoremove" "yum -y autoremove" "yum -y autoremove" "yum -y autoremove")

[[ $EUID -ne 0 ]] && red "Please run as root" && exit 1

CMD=("$(grep -i pretty_name /etc/os-release 2>/dev/null | cut -d \" -f2)" "$(hostnamectl 2>/dev/null | grep -i system | cut -d : -f2)" "$(lsb_release -sd 2>/dev/null)" "$(grep -i description /etc/lsb-release 2>/dev/null | cut -d \" -f2)" "$(grep . /etc/redhat-release 2>/dev/null)" "$(grep . /etc/issue 2>/dev/null | cut -d \\ -f1 | sed '/^[ ]*$/d')")

for i in "${CMD[@]}"; do
    SYS="$i" && [[ -n $SYS ]] && break
done

for ((int = 0; int < ${#REGEX[@]}; int++)); do
    [[ $(echo "$SYS" | tr '[:upper:]' '[:lower:]') =~ ${REGEX[int]} ]] && SYSTEM="${RELEASE[int]}" && [[ -n $SYSTEM ]] && break
done

[[ -z $SYSTEM ]] && red "OS Not Supported" && exit 1

if [[ -z $(type -P curl) ]]; then
    if [[ ! $SYSTEM == "CentOS" ]]; then
        ${PACKAGE_UPDATE[int]}
    fi
    ${PACKAGE_INSTALL[int]} curl
fi

realip(){
    ip=$(curl -s4m8 ip.sb -k) || ip=$(curl -s6m8 ip.sb -k)
}

inst_cert(){
    green "Select certificate application method:"
    echo ""
    echo -e " ${GREEN}1.${PLAIN} Use ACME (default)"
    echo -e " ${GREEN}2.${PLAIN} Generate OpenSSL pseudo-certificate"
    echo -e " ${GREEN}3.${PLAIN} Use custom certificate"
    echo ""
    read -rp "Option [1-3]: " certInput

    # If no input is provided, default to 1 (Apply using ACME)
    if [[ -z "$certInput" ]]; then
        certInput=1
    fi
    if [[ $certInput == 1 ]]; then
        cert_path="/root/cert.crt"
        key_path="/root/private.key"

        chmod -R 777 /root # 让 Hysteria 主程序访问到 /root 目录

        if [[ -f /root/cert.crt && -f /root/private.key ]] && [[ -s /root/cert.crt && -s /root/private.key ]] && [[ -f /root/ca.log ]]; then
            domain=$(cat /root/ca.log)
            green "Existing certificate detected for domain: $domain, applying"
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
            
            read -p "Enter domain to apply for certificate: " domain
            [[ -z $domain ]] && red "Invalid input, exiting script" && exit 1
            green "Confirmed:$domain" && sleep 1
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
                    green "Certificate and key generated successfully and saved in /root directory."
                    yellow "Certificate path: /root/cert.crt"
                    yellow "Key path: /root/private.key"
                    hy_domain=$domain
                fi
            else
                red "Domain name provided cannot be resolved"
                exit 1
            fi
        fi
    elif [[ $certInput == 3 ]]; then
        read -p "Enter public key (CRT) path: " cert_path
        yellow "Public key path: $cert_path"
        read -p "Enter private key (KEY) path: " key_path
        yellow "Private key path: $key_path"
        read -p "Enter certificate domain: " domain
        yellow "Certificate domain: $domain"
        hy_domain=$domain
    else
        green "Using self-signed certificate (OpenSSL)"
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

    read -p "SET Hysteria 2 PORT [1-65535] (DEFAULT FOR RANDOM): " port
    [[ -z $port ]] && port=$(shuf -i 2000-65535 -n 1)
    until [[ -z $(ss -tunlp | grep -w udp | awk '{print $5}' | sed 's/.*://g' | grep -w "$port") ]]; do
        if [[ -n $(ss -tunlp | grep -w udp | awk '{print $5}' | sed 's/.*://g' | grep -w "$port") ]]; then
            echo -e "${RED} PORT $port ${PLAIN} IS ALREADY IN USED. PLEASE RETRY A DIFFERENT PORT"
            read -p "SET Hysteria 2 PORT [1-65535] (DEFAULT FOR RANDOM): " port
            [[ -z $port ]] && port=$(shuf -i 2000-65535 -n 1)
        fi
    done


    yellow "Confirmed:$port"
    inst_jump
}

inst_jump() {
    green "Hysteria 2 Port Usage Mode:"
    echo ""
    echo -e " ${GREEN}1.${PLAIN} Single Port Mode ${YELLOW}(DEFAULT)${PLAIN}"
    echo -e " ${GREEN}2.${PLAIN} Port Range Hopping"
    echo ""
    read -rp "Option [1-2]: " jumpInput
    if [[ $jumpInput == 2 ]]; then
        read -p "Enter start port for range (recommended 10000-65535): " firstport
        read -p "Enter end port for range (must be greater than start port): " endport
        while [[ $firstport -ge $endport ]]; do
            red "Start port must be less than end port. Please re-enter start and end ports."
            read -p "Enter start port for range (recommended 10000-65535): " firstport
            read -p "Enter end port for range (recommended 10000-65535, must be greater than start port): " endport
        done
        iptables -t nat -A PREROUTING -p udp --dport $firstport:$endport  -j DNAT --to-destination :$port
        ip6tables -t nat -A PREROUTING -p udp --dport $firstport:$endport  -j DNAT --to-destination :$port
        netfilter-persistent save >/dev/null 2>&1
    else
        red "Continuing in single port mode."
    fi
}


inst_pwd() {
    read -p "Enter password (default random): " auth_pwd
    [[ -z $auth_pwd ]] && auth_pwd=$(date +%s%N | md5sum | cut -c 1-8)
    yellow "Confirmed: $auth_pwd"
}

inst_site() {
    read -rp "Enter masquerade site URL (omit https://) [default SEGA Japan]: " proxysite
    [[ -z $proxysite ]] && proxysite="maimai.sega.jp"
    yellow "Confirmed: $proxysite"
}


insthysteria(){

    if netstat -tuln | grep -q ":80 "; then
        echo "Port 80 is already in use. Exiting..."
        exit 1
    fi

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
        green "Installation successful."
    else
        red "Installation failed."
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

    # Check if inst_cert is set to "echo -e " ${GREEN}1.${PLAIN} Use ACME (default)""
    if [[ $certInput == 1 ]]; then
        last_ip=$domain
    else
        # Add brackets to IPv6 addresses
        if [[ -n $(echo $ip | grep ":") ]]; then
            last_ip="[$ip]"
        else
            last_ip=$ip
        fi
    fi

    mkdir /root/hy

    url="hysteria2://$auth_pwd@$last_ip:$last_port/?insecure=1&sni=$hy_domain"
    echo $url > /root/hy/url.txt
    nohopurl="hysteria2://$auth_pwd@$last_ip:$port/?insecure=1&sni=$hy_domain"
    echo $nohopurl > /root/hy/url-nohop.txt
    surge_format="TEST HY2 = hysteria2, $last_ip, $last_port, password=$auth_pwd, sni=$hy_domain, download-bandwidth=1000, skip-cert-verify=true"
    echo $surge_format > /root/hy/HY4SURGE.txt

    systemctl daemon-reload
    systemctl enable hysteria-server
    systemctl start hysteria-server
    if [[ -n $(systemctl status hysteria-server 2>/dev/null | grep -w active) && -f '/etc/hysteria/config.yaml' ]]; then
        green "Hysteria 2 started successfully."
    else
        red "Hysteria 2 failed to start. Try 'systemctl status hysteria-server' for details. Exiting." && exit 1
    fi
    blue "A faint clap of thunder, Clouded skies."
    green "Hysteria 2 installed successfully."
    yellow "Hysteria 2 proxy share link (path: /root/hy/url.txt):"
    red "$(cat /root/hy/url.txt)"
    yellow "Hysteria 2 single port share link (path: /root/hy/url-nohop.txt):"
    red "$(cat /root/hy/url-nohop.txt)"
    yellow "Hysteria 2 proxy share info for SURGE (path: /root/hy/HY4SURGE.txt):"
    red "$(cat /root/hy/HY4SURGE.txt)"
}

unsthysteria(){
    systemctl stop hysteria-server.service >/dev/null 2>&1
    systemctl disable hysteria-server.service >/dev/null 2>&1
    rm -f /lib/systemd/system/hysteria-server.service /lib/systemd/system/hysteria-server@.service
    rm -rf /usr/local/bin/hysteria /etc/hysteria /root/hy /root/hysteria.sh
    iptables -t nat -F PREROUTING >/dev/null 2>&1
    netfilter-persistent save >/dev/null 2>&1

    green "Uninstalled successfully"
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
    light_purple "Perhaps rain comes."
    light_purple "If so, will you stay here with me?"
    echo ""
    echo -e " ${GREEN}1.${PLAIN} Start"
    echo -e " ${GREEN}2.${PLAIN} Shutdown"
    echo -e " ${GREEN}3.${PLAIN} Restart"
    echo ""
    read -rp "Option [0-3]: " switchInput
    case $switchInput in
        1 ) starthysteria ;;
        2 ) stophysteria ;;
        3 ) stophysteria && starthysteria ;;
        * ) exit 1 ;;
    esac
}

changeport(){
    oldport=$(cat /etc/hysteria/config.yaml 2>/dev/null | sed -n 1p | awk '{print $2}' | awk -F ":" '{print $2}')
    
    read -p "ENTER Hysteria 2 PORT [1-65535] (PRESS ENTER FOR RANDOM PORT): " port
    [[ -z $port ]] && port=$(shuf -i 2000-65535 -n 1)

    until [[ -z $(ss -tunlp | grep -w udp | awk '{print $5}' | sed 's/.*://g' | grep -w "$port") ]]; do
        if [[ -n $(ss -tunlp | grep -w udp | awk '{print $5}' | sed 's/.*://g' | grep -w "$port") ]]; then
            echo -e "${RED} PORT $port ${PLAIN} IS ALREADY IN USE BY ANOTHER APPLICATION. PLEASE CHOOSE A DIFFERENT PORT!"
            read -p "SET Hysteria 2 PORT [1-65535] (PRESS ENTER FOR RANDOM PORT): " port
            [[ -z $port ]] && port=$(shuf -i 2000-65535 -n 1)
        fi
    done

    sed -i "1s#$oldport#$port#g" /etc/hysteria/config.yaml
    sed -i "1s#$oldport#$port#g" /root/hy/HY4SURGE.txt

    stophysteria && starthysteria

    green "Port updated: $port"
    showconf
}

changepasswd(){
    oldpasswd=$(cat /etc/hysteria/config.yaml 2>/dev/null | sed -n 15p | awk '{print $2}')

    read -p "ENTER Hysteria 2 PASSWORD (PRESS ENTER FOR RANDOM): " passwd
    [[ -z $passwd ]] && passwd=$(date +%s%N | md5sum | cut -c 1-8)

    sed -i "1s#$oldpasswd#$passwd#g" /etc/hysteria/config.yaml
    sed -i "1s#$oldpasswd#$passwd#g" /root/hy/HY4SURGE.txt

    stophysteria && starthysteria

    green "password updated: $auth_pwd"
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

    green "Certificate updated"
    showconf
}

changeproxysite(){
    oldproxysite=$(cat /etc/hysteria/config.yaml | grep url | awk -F " " '{print $2}' | awk -F "https://" '{print $2}')
    
    inst_site

    sed -i "s#$oldproxysite#$proxysite#g" /etc/caddy/Caddyfile

    stophysteria && starthysteria

    green "shell-site updated: $proxysite"
}

changeconf() {
    green "Hysteria 2 Configuration Menu:"
    echo -e " ${GREEN}1.${PLAIN} Modify port"
    echo -e " ${GREEN}2.${PLAIN} Modify password"
    echo -e " ${GREEN}3.${PLAIN} Modify certificate"
    echo -e " ${GREEN}4.${PLAIN} Modify masquerade site"
    echo ""
    read -p " Please select an option [1-4]: " confAnswer
    case $confAnswer in
        1 ) changeport ;;
        2 ) changepasswd ;;
        3 ) change_cert ;;
        4 ) changeproxysite ;;
        * ) exit 1 ;;
    esac
}

showconf(){
    yellow "Hysteria 2 share link:"
    red "$(cat /root/hy/url.txt)"
    yellow "Hysteria 2 single port share link:"
    red "$(cat /root/hy/url-nohop.txt)"
    yellow "Hysteria 2 proxy info for SURGE:"
    red "$(cat /root/hy/HY4SURGE.txt)"
}

update_core(){
    # ReInstall Hysteria 2
    bash <(curl -fsSL https://get.hy2.sh/)
}

menu() {
    clear
    echo -e " ${LIGHT_PURPLE}Hysteria 2${PLAIN}"
    echo ""
    echo -e " ${UNDERLINE_PURPLE}At what speed must i live, to be able to see you again?${PLAIN}"
    echo " --------------------------------------------------------------------------------"
    echo -e " ${LIGHT_GREEN}1.${PLAIN} Install"
    echo -e " ${LIGHT_GREEN}2.${PLAIN} ${RED}Uninstall${PLAIN}"
    echo " --------------------------------------------------------------------------------"
    echo -e " ${LIGHT_GRAY}3.${PLAIN} Stop, Start, Restart"
    echo -e " ${LIGHT_GRAY}4.${PLAIN} Modify config"
    echo -e " ${LIGHT_GRAY}5.${PLAIN} Display config"
    echo " --------------------------------------------------------------------------------"
    echo -e " ${LIGHT_YELLOW}6.${PLAIN} Update core"
    echo " --------------------------------------------------------------------------------"
    echo -e " ${PURPLE}0.${PLAIN} Exit"
    echo ""
    read -rp "Option [0-5]: " menuInput
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
