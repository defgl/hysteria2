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

# 定义一个包含所有要安装的软件包的数组
# 对于需要特殊检查命令的软件包，使用 "包名:检查命令" 的格式
packages=("curl" "net-tools:ifconfig" "jq")

install_packages() {
    # 更新软件源一次
    echo "Updating software repositories..."
    sudo $PACKAGE_MANAGER update

    local package check_command
    for item in "$@"; do  # 使用"$@"来接收传递给函数的所有参数
        # 如果软件包定义中包含 ":", 则拆分为包名和检查命令
        if [[ $item == *":"* ]]; then
            IFS=":" read -r package check_command <<< "$item"
        else
            package=$item
            check_command=$item
        fi

        if ! command -v $check_command > /dev/null; then
            echo "Installing $package..."
            sudo $PACKAGE_MANAGER install -y $package
        else
            echo "$package is already installed."
        fi
    done
}



# 确定使用哪个包管理器
DISTRO=$(lsb_release -is)
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

# 调用函数来安装所有软件包
install_packages

# 实际的 IP 地址获取函数
realip() { 
    ip=$(curl -s api.ipify.org) || ip=$(curl -s api64.ipify.org)
}

# 证书申请函数
inst_cert() {
    echo "Select certificate application method:"
    echo ""
    echo "1. Use ACME (default)"
    echo "2. Generate OpenSSL pseudo-certificate"
    echo "3. Use custom certificate"
    echo ""
    read -rp "Option [1-3]: " certInput

    if [[ -z "$certInput" ]]; then
        certInput=1
    fi

    if [[ $certInput == 1 ]]; then
        cert_path="/root/cert.crt"
        key_path="/root/private.key"
        chmod -R 777 /root

        # 获取实际的IP地址
        realip

        # 域名输入和确认
        read -p "Enter the domain name for certificate application: " domain
        [[ -z "$domain" ]] && { echo "No input detected. Exiting."; exit 1; }
        echo "Domain confirmed: $domain"
        sleep 1

        # 域名解析验证
        domainIP=$(curl -s "http://ip-api.com/json/${domain}" | jq -r '.query')
        if [[ -z $domainIP ]]; then
            echo "Domain name provided cannot be resolved. Exiting."
            exit 1
        fi

        # 根据系统动态添加cron软件包
        local additional_packages=("curl" "wget" "socat" "openssl" "qrencode" "procps")
        if [[ "$DISTRO" == "CentOS" || "$DISTRO" == "Fedora" ]]; then
            additional_packages+=("cronie")  # CentOS/Fedora 使用 cronie
        else
            additional_packages+=("cron")  # Debian/Ubuntu 使用 cron
        fi
    
        # 动态安装所有必需软件包
        install_packages "${additional_packages[@]}"

        # Acme 证书申请逻辑
        curl https://get.acme.sh | sh
        source ~/.bashrc || source ~/.profile
        ~/.acme.sh/acme.sh --upgrade --auto-upgrade
        ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt

        if [[ -n $(echo $ip | grep ":") ]]; then
            ~/.acme.sh/acme.sh --issue -d $domain --standalone -k ec-256 --listen-v6 --insecure
        else
            ~/.acme.sh/acme.sh --issue -d $domain --standalone -k ec-256 --insecure
        fi

        ~/.acme.sh/acme.sh --install-cert -d $domain --key-file $key_path --fullchain-file $cert_path --ecc

        if [[ -f $cert_path && -f $key_path ]] && [[ -s $cert_path && -s $key_path ]]; then
            echo $domain > /root/ca.log
            # 添加自动续期的Cron任务
            (crontab -l 2>/dev/null; echo "0 0 * * * ~/.acme.sh/acme.sh --cron --home ~/.acme.sh > /dev/null") | crontab -
            echo "Certificate and key generated successfully and saved in /root directory."
            echo "Certificate path: $cert_path"
            echo "Key path: $key_path"
            hy_domain=$domain
        else
            echo "Failed to issue certificate."
            exit 1
        fi

    elif [[ $certInput == 3 ]]; then
        # 自定义证书逻辑
        read -p "Enter public key (CRT) path: " cert_path
        echo "Public key path: $cert_path"
        read -p "Enter private key (KEY) path: " key_path
        echo "Private key path: $key_path"
        read -p "Enter certificate domain: " domain
        echo "Certificate domain: $domain"
        hy_domain=$domain
    else
        # OpenSSL 伪证书生成逻辑
        cert_path="/etc/hysteria/cert.crt"
        key_path="/etc/hysteria/private.key"
        openssl ecparam -genkey -name prime256v1 -out $key_path
        openssl req -new -x509 -days 36500 -key $key_path -out $cert_path -subj "/CN=$domain"
        echo "Self-signed certificate and key generated successfully."
        echo "Certificate path: $cert_path"
        echo "Key path: $key_path"
        hy_domain="www.example.com"
        domain="www.example.com"
    fi
}


inst_port(){
    iptables -t nat -F PREROUTING >/dev/null 2>&1

    read -p "Set Hysteria 2 port [1-65535] (default for random): " port
    [[ -z $port ]] && port=$(shuf -i 2000-65535 -n 1)
    while [[ $port -lt 1 || $port -gt 65535 || -n $(ss -tunlp | grep -w udp | awk '{print $5}' | sed 's/.*://g' | grep -w "$port") ]]; do
        if [[ $port -lt 1 || $port -gt 65535 ]]; then
            echo -e "${RED} Port $port ${PLAIN} is not in the range 1-65535. Please retry a different port"
        elif [[ -n $(ss -tunlp | grep -w udp | awk '{print $5}' | sed 's/.*://g' | grep -w "$port") ]]; then
            echo -e "${RED} Port $port ${PLAIN} is already in used. Please retry a different port"
        fi
        read -p "Set Hysteria 2 port [1-65535] (default for random): " port
        [[ -z $port ]] && port=$(shuf -i 2000-65535 -n 1)
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
    [[ -z $auth_pwd ]] && auth_pwd=$(tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 14)
    yellow "Confirmed: $auth_pwd"
}

inst_site() {
    echo "Please enter the URL of the site you want to use for masquerading."
    echo "Note: Do not include 'https://'. For example, if you want to use 'https://example.com', just enter 'example.com'."
    echo "If you don't enter a site, 'www.playstation.com' will be used by default."
    read -rp "Enter masquerade site URL: " proxysite
    proxysite=${proxysite:-www.playstation.com}
    green -e "Confirmed masquerade site: $proxysite"
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

        # 构建基础软件包列表
    local packages=("curl" "wget" "socat" "openssl" "qrencode" "procps" "net-tools")

    # 对于特定发行版，添加特定的软件包
    if [[ "$DISTRO" == "Ubuntu" || "$DISTRO" == "Debian" ]]; then
        packages+=("iptables-persistent" "netfilter-persistent")
    elif [[ "$DISTRO" == "CentOS" || "$DISTRO" == "Fedora" ]]; then
        # CentOS, Fedora 或其他RHEL系列发行版特定的包处理（如果有）
        # 注意: CentOS/Fedora 通常使用 firewalld，可能不需要 iptables-persistent 等包
        echo "No additional packages required for $DISTRO"
    fi

        # 使用动态软件包列表安装软件包
    install_packages "${packages[@]}"


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
    surge_format="NodeName = hysteria2, $last_ip, $last_port, password=$auth_pwd, sni=$hy_domain, download-bandwidth=1000, skip-cert-verify=true"
    echo $surge_format > /root/hy/HY4SURGE.txt

    systemctl daemon-reload
    systemctl enable hysteria-server
    systemctl start hysteria-server
    if [[ -n $(systemctl status hysteria-server 2>/dev/null | grep -w active) && -f '/etc/hysteria/config.yaml' ]]; then
        green "Hysteria 2 started successfully."
    else
        red "Hysteria 2 failed to start. Try 'systemctl status hysteria-server' for details. Exiting." && exit 1
    fi
    echo ""
    blue "A faint clap of thunder, Clouded skies."
    blue "Perhaps rain comes."
    #green "Hysteria 2 installed successfully."
    #yellow "General share link / Port-Hopping (path: /root/hy/url.txt):"
    #red "$(cat /root/hy/url.txt)"
    #yellow "General share link / Single-Port (path: /root/hy/url-nohop.txt):"
    #red "$(cat /root/hy/url-nohop.txt)"
    #cyan "SURGE (path: /root/hy/HY4SURGE.txt):"
    #cyan "Proxy is ready."
    #cyan "--- ___ ---"
    echo ""
    cyan " ^_^ ^_^"
    cyan "   ^_^  "
    echo ""
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

    while [[ $port -lt 1 || $port -gt 65535 || -n $(ss -tunlp | grep -w udp | awk '{print $5}' | sed 's/.*://g' | grep -w "$port") ]]; do
        if [[ $port -lt 1 || $port -gt 65535 ]]; then
            echo -e "${RED} Port $port ${PLAIN} is not in the range 1-65535. Please retry a different port"
        elif [[ -n $(ss -tunlp | grep -w udp | awk '{print $5}' | sed 's/.*://g' | grep -w "$port") ]]; then
            echo -e "${RED} Port $port ${PLAIN} is already in use. Please choose a different port!"
        fi
        read -p "Set Hysteria 2 port [1-65535] (default for random port): " port
        [[ -z $port ]] && port=$(shuf -i 2000-65535 -n 1)
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
    echo -e " ${random_color}At what speed must i live, to be able to see you again?${PLAIN}"
    echo ""
    #echo -e " ${random_color}Hysteria 2${PLAIN}"
    #echo " --------------------------------------------------------------------------------"
    echo -e " ${LIGHT_GREEN}1.${PLAIN} ${cyan}Install${PLAIN}"
    echo -e " ${LIGHT_GREEN}2.${PLAIN} Uninstall"
    #echo " --------------------------------------------------------------------------------"
    echo ""
    echo -e " ${LIGHT_GRAY}3.${PLAIN} Stop, Start, Restart"
    echo -e " ${LIGHT_GRAY}4.${PLAIN} Modify config"
    echo -e " ${LIGHT_GRAY}5.${PLAIN} Display config"
    echo ""
    #echo " --------------------------------------------------------------------------------"
    echo -e " ${LIGHT_YELLOW}6.${PLAIN} Update core"
    #echo " --------------------------------------------------------------------------------"
    echo ""
    echo -e " ${PURPLE}0.${PLAIN} Exit"
    #echo " --------------------------------------------------------------------------------"
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
