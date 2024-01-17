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

random_color() {
  colors=("31" "32" "33" "34" "35" "36" "37")
  echo -e "\e[${colors[$((RANDOM % 7))]}m$1\e[0m"
}

DISTRO=$(lsb_release -is)

# 确定使用哪个包管理器
case $DISTRO in
  Ubuntu|Debian)
    PACKAGE_MANAGER="apt"
    ;;
  CentOS|RedHat|Fedora)
    PACKAGE_MANAGER="yum"
    ;;
  *)
    echo "Unsupported distro"
    exit 1
    ;;  
esac

# 调用函数来安装软件包
install_package "curl"
install_package "net-tools"
install_package "jq"

install_package() {
    local package=$1
    if ! command -v $package > /dev/null; then
        echo "Installing $package..."
        sudo $PACKAGE_MANAGER update
        sudo $PACKAGE_MANAGER install -y $package
    else
        echo "$package is already installed."
    fi
}


realip(){
    ip=$(curl -s4m8 ip.sb -k) || ip=$(curl -s6m8 ip.sb -k)
}

inst_cert() {
    green "Select certificate application method:"
    echo ""
    echo -e " ${GREEN}1.${PLAIN} Use ACME (default)"
    echo -e " ${GREEN}2.${PLAIN} Generate OpenSSL pseudo-certificate"
    echo -e " ${GREEN}3.${PLAIN} Use custom certificate"
    echo ""
    read -rp "Option [1-3]: " certInput

    if [[ -z "$certInput" ]]; then
        certInput=1
    fi

   if [[ $certInput == 1 ]]; then
    cert_path="/root/cert.crt"
    key_path="/root/private.key"
    chmod -R 777 /root

    # Check for existing certificate and keys
    if [[ -f $cert_path && -f $key_path ]] && [[ -s $cert_path && -s $key_path ]] && [[ -f /root/ca.log ]]; then
        domain=$(cat /root/ca.log)
        green "Existing certificate detected for domain: $domain, applying"
        hy_domain=$domain
    else
        # Handle WARP status
        handleWARP() {
            local WARPv4Status=$(curl -s4m8 https://www.cloudflare.com/cdn-cgi/trace -k | grep warp | cut -d= -f2)
            local WARPv6Status=$(curl -s6m8 https://www.cloudflare.com/cdn-cgi/trace -k | grep warp | cut -d= -f2)
            if [[ $WARPv4Status =~ on|plus ]] || [[ $WARPv6Status =~ on|plus ]]; then
                wg-quick down wgcf >/dev/null 2>&1
                systemctl stop warp-go >/dev/null 2>&1
                realip
                wg-quick up wgcf >/dev/null 2>&1
                systemctl start warp-go >/dev/null 2>&1
            else
                realip
            fi
        }

        handleWARP

        # Get Domain Name
        read -p "Enter the domain name for certificate application: " domain
        [[ -z "$domain" ]] && { echo -e "${RED}No input detected. Exiting.${PLAIN}"; exit 1; }
        echo -e "${GREEN}Domain confirmed: $domain${PLAIN}"
        sleep 1

        # Domain Resolution
        resolveDomain() {
            local domainIP=$(dig @8.8.8.8 +time=2 +short "$1" 2>/dev/null)
            [[ -z $domainIP ]] && domainIP=$(dig @2001:4860:4860::8888 +time=2 aaaa +short "$1" 2>/dev/null)
            echo $domainIP
        }
        
        domainIP=$(resolveDomain "$domain")
        
        # If domainIP is still empty, use another method
        if [[ -z $domainIP ]]; then
            domainIP=$(curl -sm8 ipget.net/?ip="${domain}")
            if [[ -z $domainIP || -n $(echo $domainIP | grep "nginx") ]]; then
                domainIP=$(echo "$(nslookup $domain 2>&1)" | awk '{print $NF}')
            fi
        fi
        
        # If domainIP is still empty after all methods, exit with error
        [[ -z $domainIP ]] && { echo -e "${RED}Domain name provided cannot be resolved${PLAIN}"; exit 1; }
        
        # Certificate Generation
        generateCertificate() {
            sudo $PACKAGE_MANAGER install -y curl wget sudo socat openssl
            [[ $DISTRO = "CentOS" ]] && sudo $PACKAGE_MANAGER install -y cronie && systemctl start crond && systemctl enable crond
            [[ $DISTRO != "CentOS" ]] && sudo $PACKAGE_MANAGER install -y cron && systemctl start cron && systemctl enable cron

            curl https://get.acme.sh | sh -s email=$(date +%s%N | md5sum | cut -c 1-16)@gmail.com
            source ~/.bashrc
            bash ~/.acme.sh/acme.sh --upgrade --auto-upgrade
            bash ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt
            local issueCommand="bash ~/.acme.sh/acme.sh --issue -d ${1} --standalone -k ec-256 --insecure"
            [[ -n $(echo $ip | grep ":") ]] && issueCommand+=" --listen-v6"
            eval $issueCommand
            bash ~/.acme.sh/acme.sh --install-cert -d ${1} --key-file /root/private.key --fullchain-file /root/cert.crt --ecc

            if [[ -f $cert_path && -f $key_path ]] && [[ -s $cert_path && -s $key_path ]]; then
                echo $1 > /root/ca.log
                sed -i '/--cron/d' /etc/crontab >/dev/null 2>&1
                echo "0 0 * * * root bash /root/.acme.sh/acme.sh --cron -f >/dev/null 2>&1" >> /etc/crontab
                green "Certificate and key generated successfully and saved in /root directory."
                yellow "Certificate path: $cert_path"
                yellow "Key path: $key_path"
                hy_domain=$1
            fi
        }

        [[ $domainIP == $ip ]] && generateCertificate "$domain" || { red "Domain name provided cannot be resolved"; exit 1; }
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

    read -p "Set Hysteria 2 port [1-65535] (default for random): " port
    [[ -z $port ]] && port=$(shuf -i 2000-65535 -n 1)
    until [[ -z $(ss -tunlp | grep -w udp | awk '{print $5}' | sed 's/.*://g' | grep -w "$port") ]]; do
        if [[ -n $(ss -tunlp | grep -w udp | awk '{print $5}' | sed 's/.*://g' | grep -w "$port") ]]; then
            echo -e "${RED} Port $port ${PLAIN} is already in used. Please retry a different port"
            read -p "Set Hysteria 2 port [1-65535] (default for random): " port
            [[ -z $port ]] && port=$(shuf -i 2000-65535 -n 1)
        fi
    done


    yellow "Confirmed:$port"
    inst_jump
}

inst_jump() {
    green "Hysteria 2 port usage mode:"
    echo ""
    echo -e " ${GREEN}1.${PLAIN} Single port ${YELLOW}(DEFAULT)${PLAIN}"
    echo -e " ${GREEN}2.${PLAIN} Port range hopping"
    echo ""
    read -rp "Option [1-2]: " jumpInput
    if [[ $jumpInput == 2 ]]; then
        read -p "Enter start port for range (recommended 10000-65535): " firstport
        read -p "Enter end port for range (must be greater than start port): " endport
        while [[ $firstport -ge $endport ]]; do
            red "Start port must be less than end port. Please retry start and end ports."
            read -p "Enter start port for range (recommended 10000-65535): " firstport
            read -p "Enter end port for range (recommended 10000-65535, must be greater than start port): " endport
        done
        iptables -t nat -A PREROUTING -p udp --dport $firstport:$endport  -j DNAT --to-destination :$port
        ip6tables -t nat -A PREROUTING -p udp --dport $firstport:$endport  -j DNAT --to-destination :$port
        netfilter-persistent save >/dev/null 2>&1
    else
        red "Continuing in single port."
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

    if [ $DISTRO = "CentOS" ]; then
      sudo $PACKAGE_MANAGER install -y curl wget sudo qrencode procps iptables-persistent net-tools
    else
      sudo $PACKAGE_MANAGER update
      sudo $PACKAGE_MANAGER install -y curl wget sudo qrencode procps iptables-persistent net-tools  
    fi


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
  initStreamReceiveWindow: 8388608 
  maxStreamReceiveWindow: 8388608 
  initConnReceiveWindow: 20971520 
  maxConnReceiveWindow: 20971520 
  maxIdleTimeout: 30s 
  maxIncomingStreams: 1024 
  disablePathMTUDiscovery: false 

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
    surge_format="🇺🇳 NodeName = hysteria2, $last_ip, $last_port, password=$auth_pwd, sni=$hy_domain, download-bandwidth=1000, skip-cert-verify=true"
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
    #yellow "General share link / Port-Hopping (path: /root/hy/url.txt):"
    #red "$(cat /root/hy/url.txt)"
    #yellow "General share link / Single-Port (path: /root/hy/url-nohop.txt):"
    #red "$(cat /root/hy/url-nohop.txt)"
    #cyan "SURGE (path: /root/hy/HY4SURGE.txt):"
    cyan "Surge | Node is ready now."
    cyan "$(cat /root/hy/HY4SURGE.txt)"
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
    random_color "Perhaps rain comes."
    random_color "If so, will you stay here with me?"
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
    
    read -p "Enter Hysteria 2 port [1-65535] (default for random port): " port
    [[ -z $port ]] && port=$(shuf -i 2000-65535 -n 1)

    until [[ -z $(ss -tunlp | grep -w udp | awk '{print $5}' | sed 's/.*://g' | grep -w "$port") ]]; do
        if [[ -n $(ss -tunlp | grep -w udp | awk '{print $5}' | sed 's/.*://g' | grep -w "$port") ]]; then
            echo -e "${RED} Port $port ${PLAIN} is already in use. Please choose a different port!"
            read -p "Set Hysteria 2 port [1-65535] (default for random port): " port
            [[ -z $port ]] && port=$(shuf -i 2000-65535 -n 1)
        fi
    done

    sed -i "1s#$oldport#$port#g" /etc/hysteria/config.yaml
    sed -i "1s#$oldport#$port#g" /root/hy/HY4SURGE.txt

    stophysteria && starthysteria

    green "port updated: $port"
    showconf
}

changepasswd(){
    oldpasswd=$(cat /etc/hysteria/config.yaml 2>/dev/null | sed -n 15p | awk '{print $2}')

    read -p "Enter Hysteria 2 password (default for random): " passwd
    [[ -z $passwd ]] && passwd=$(< /dev/urandom tr -dc A-Za-z0-9 | head -c14)

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

    green "certificate updated"
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
    echo -e " ${random_color}Hysteria 2${PLAIN}"
    echo ""
    echo -e " ${UNDERLINE_PURPLE}At what speed must i live, to be able to see you again?${PLAIN}"
    # echo " --------------------------------------------------------------------------------"
    echo -e " ${LIGHT_GREEN}1.${PLAIN} Install"
    echo -e " ${LIGHT_GREEN}2.${PLAIN} ${RED}Uninstall${PLAIN}"
    # echo " --------------------------------------------------------------------------------"
    echo -e " ${LIGHT_GRAY}3.${PLAIN} Stop, Start, Restart"
    echo -e " ${LIGHT_GRAY}4.${PLAIN} Modify config"
    echo -e " ${LIGHT_GRAY}5.${PLAIN} Display config"
    # echo " --------------------------------------------------------------------------------"
    echo -e " ${LIGHT_YELLOW}6.${PLAIN} Update core"
    # echo " --------------------------------------------------------------------------------"
    echo -e " ${PURPLE}0.${PLAIN} Exit"
    echo " --------------------------------------------------------------------------------"
    #echo ""
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
