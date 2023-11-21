#!/bin/bash

export LANG=en_US.UTF-8

RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
BLUE="\033[34m"
MAGENTA="\033[35m"
CYAN="\033[36m"
WHITE="\033[37m"
PLAIN="\033[0m"
# BEGIN: 1a2b3c4d5e6f
GRAY="\033[90m"
LIGHT_RED="\033[91m"
LIGHT_GREEN="\033[92m"
LIGHT_YELLOW="\033[93m"
LIGHT_BLUE="\033[94m"
# END: 1a2b3c4d5e6f

red(){
    echo -e "\033[31m\033[01m$1\033[0m"
}

green(){
    echo -e "\033[32m\033[01m$1\033[0m"
}

yellow(){
    echo -e "\033[33m\033[01m$1\033[0m"
}

# Define system types and their corresponding package management commands
REGEX=("debian" "ubuntu" "centos|red hat|kernel|oracle linux|alma|rocky" "'amazon linux'" "fedora")
RELEASE=("Debian" "Ubuntu" "CentOS" "CentOS" "Fedora")
PACKAGE_UPDATE=("apt-get update" "apt-get update" "yum -y update" "yum -y update" "yum -y update")
PACKAGE_INSTALL=("apt -y install" "apt -y install" "yum -y install" "yum -y install" "yum -y install")
PACKAGE_REMOVE=("apt -y remove" "apt -y remove" "yum -y remove" "yum -y remove" "yum -y remove")
PACKAGE_UNINSTALL=("apt -y autoremove" "apt -y autoremove" "yum -y autoremove" "yum -y autoremove" "yum -y autoremove")

[[ $EUID -ne 0 ]] && echo "PLEASE RUN THIS SCRIPT AS ROOT" && exit 1

CMD=("$(grep -i pretty_name /etc/os-release 2>/dev/null | cut -d \" -f2)" "$(hostnamectl 2>/dev/null | grep -i system | cut -d : -f2)" "$(lsb_release -sd 2>/dev/null)" "$(grep -i description /etc/lsb-release 2>/dev/null | cut -d \" -f2)" "$(grep . /etc/redhat-release 2>/dev/null)" "$(grep . /etc/issue 2>/dev/null | cut -d \\ -f1 | sed '/^[ ]*$/d')")

for i in "${CMD[@]}"; do
    SYS="$i" && [[ -n $SYS ]] && break
done

for ((int = 0; int < ${#REGEX[@]}; int++)); do
    [[ $(echo "$SYS" | tr '[:upper:]' '[:lower:]') =~ ${REGEX[int]} ]] && SYSTEM="${RELEASE[int]}" && [[ -n $SYSTEM ]] && break
done

[[ -z $SYSTEM ]] && echo "YOUR OPERATING SYSTEM IS NOT SUPPORTED" && exit 1

if [[ -z $(type -P curl) ]]; then
    if [[ ! $SYSTEM == "CentOS" ]]; then
        ${PACKAGE_UPDATE[int]}
    fi
    ${PACKAGE_INSTALL[int]} curl
fi

# Update the package list and install the required packages
$PKG_MANAGER update
$PKG_MANAGER install -y $REQUIRED_PACKAGES

echo "REQUIRED PACKAGES HAVE BEEN INSTALLED."

realip(){
    ip=$(curl -s4m8 ip.sb -k) || ip=$(curl -s6m8 ip.sb -k)
}

inst_cert(){
    green "Hysteria 2 协议证书申请方式如下："
    echo ""
    echo -e " ${GREEN}1.${PLAIN} 必应自签证书 ${YELLOW}（默认）${PLAIN}"
    echo -e " ${GREEN}2.${PLAIN} Acme 脚本自动申请"
    echo -e " ${GREEN}3.${PLAIN} 自定义证书路径"
    echo ""
    read -rp "请输入选项 [1-3]: " certInput
    if [[ $certInput == 2 ]]; then
        cert_path="/root/cert.crt"
        key_path="/root/private.key"

        chmod -R 777 /root # 让 Hysteria 主程序访问到 /root 目录

        if [[ -f /root/cert.crt && -f /root/private.key ]] && [[ -s /root/cert.crt && -s /root/private.key ]] && [[ -f /root/ca.log ]]; then
            domain=$(cat /root/ca.log)
            green "检测到原有域名：$domain 的证书，正在应用"
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
            
            read -p "请输入需要申请证书的域名：" domain
            [[ -z $domain ]] && red "未输入域名，无法执行操作！" && exit 1
            green "已输入的域名：$domain" && sleep 1
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
                    green "证书申请成功! 脚本申请到的证书 (cert.crt) 和私钥 (private.key) 文件已保存到 /root 文件夹下"
                    yellow "证书crt文件路径如下: /root/cert.crt"
                    yellow "私钥key文件路径如下: /root/private.key"
                    hy_domain=$domain
                fi
            else
                red "当前域名解析的IP与当前VPS使用的真实IP不匹配"
                green "建议如下："
                yellow "1. 请确保CloudFlare小云朵为关闭状态(仅限DNS), 其他域名解析或CDN网站设置同理"
                yellow "2. 请检查DNS解析设置的IP是否为VPS的真实IP"
                yellow "3. 脚本可能跟不上时代, 建议截图发布到GitHub Issues、GitLab Issues、论坛或TG群询问"
                exit 1
            fi
        fi
    elif [[ $certInput == 3 ]]; then
        read -p "请输入公钥文件 crt 的路径：" cert_path
        yellow "公钥文件 crt 的路径：$cert_path "
        read -p "请输入密钥文件 key 的路径：" key_path
        yellow "密钥文件 key 的路径：$key_path "
        read -p "请输入证书的域名：" domain
        yellow "证书域名：$domain"
        hy_domain=$domain
    else
        green "将使用必应自签证书作为 Hysteria 2 的节点证书"

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

    read -p "SET HYSTERIA PORT [1-65535] (PRESS ENTER FOR RANDOM PORT): " port
    [[ -z $port ]] && port=$(shuf -i 2000-65535 -n 1)
    until [[ -z $(ss -tunlp | grep -w udp | awk '{print $5}' | sed 's/.*://g' | grep -w "$port") ]]; do
        if [[ -n $(ss -tunlp | grep -w udp | awk '{print $5}' | sed 's/.*://g' | grep -w "$port") ]]; then
            echo -e "${LIGHT_RED} $port ${PLAIN} PORT IS ALREADY IN USE BY ANOTHER PROGRAM, PLEASE TRY A DIFFERENT PORT!"
            read -p "SET HYSTERIA 2 PORT [1-65535] (PRESS ENTER FOR RANDOM PORT): " port
            [[ -z $port ]] && port=$(shuf -i 2000-65535 -n 1)
        fi
    done

    yellow "HYSTERIA WILL USE PORT: $port"
}

inst_jump(){
    green "HYSTERIA PORT USAGE MODES:"
    echo ""
    echo -e " ${GREEN}1.${PLAIN} SINGLE PORT ${YELLOW}(DEFAULT)${PLAIN}"
    echo -e " ${GREEN}2.${PLAIN} PORT JUMPING"
    echo ""
    read -rp "ENTER OPTION [1-2]: " jumpInput
    if [[ $jumpInput == 2 ]]; then
        read -p "SET START PORT FOR RANGE (RECOMMENDED BETWEEN 10000-65535): " firstport
        read -p "SET END PORT FOR RANGE (RECOMMENDED BETWEEN 10000-65535, MUST BE GREATER THAN START PORT): " endport
        if [[ $firstport -ge $endport ]]; then
            until [[ $firstport -le $endport ]]; do
                if [[ $firstport -ge $endport ]]; then
                    red "START PORT IS GREATER THAN END PORT, PLEASE RE-ENTER START AND END PORTS"
                    read -p "SET START PORT FOR RANGE (RECOMMENDED BETWEEN 10000-65535): " firstport
                    read -p "SET END PORT FOR RANGE (RECOMMENDED BETWEEN 10000-65535, MUST BE GREATER THAN START PORT): " endport
                fi
            done
        fi
        iptables -t nat -A PREROUTING -p udp --dport $firstport:$endport  -j DNAT --to-destination :$port
        ip6tables -t nat -A PREROUTING -p udp --dport $firstport:$endport  -j DNAT --to-destination :$port
        netfilter-persistent save >/dev/null 2>&1
    else
        red "CONTINUING WITH SINGLE PORT MODE"
    fi
}

inst_pwd(){
    read -p "SET HYSTERIA PASSWORD (PRESS ENTER FOR RANDOM CHARACTERS): " auth_pwd
    [[ -z $auth_pwd ]] && auth_pwd=$(date +%s%N | md5sum | cut -c 1-8)
    yellow "HYSTERIA PASSWORD SET TO: $auth_pwd"
}

inst_site(){
    read -rp "ENTER HYSTERIA 2 MASQUERADE SITE URL (REMOVE HTTPS://) [PRESS ENTER FOR DEFAULT]: " proxysite
    [[ -z $proxysite ]] && proxysite="maimai.sega.jp"
    yellow "HYSTERIA 2 MASQUERADE SITE SET TO: $proxysite"
}

inst_hyv2(){

    wget -N https://raw.githubusercontent.com/Misaka-blog/hysteria-install/main/hy2/install_server.sh
    bash install_server.sh
    rm -f install_server.sh

    if [[ -f "/usr/local/bin/hysteria" ]]; then
        green "HYSTERIA 2 INSTALLED SUCCESSFULLY."
    else
        red "HYSTERIA 2 INSTALLATION FAILED. PLEASE RERUN SCRIPT."
    fi

    # Ask user for Hysteria configuration
    inst_cert
    inst_port
    inst_jump
    inst_pwd
    inst_site

    # Set Hysteria configuration file
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

    # Determine final inbound port range
    last_port=${firstport:+$port,$firstport-$endport}
    last_port=${last_port:-$port}

    # Add brackets to IPv6 address
    last_ip=${ip//:/[:]}

    mkdir -p /root/hy
    cat << EOF > /root/hy/hy-client.yaml
server: $last_ip:$last_port

auth: $auth_pwd

tls:
  sni: $hy_domain
  insecure: true

quic:
  initStreamReceiveWindow: 16777216
  maxStreamReceiveWindow: 16777216
  initConnReceiveWindow: 33554432
  maxConnReceiveWindow: 33554432

fastOpen: true

socks5:
  listen: 127.0.0.1:5080

transport:
  udp:
    hopInterval: 30s 
EOF
    cat << EOF > /root/hy/hy-client.json
{
  "server": "$last_ip:$last_port",
  "auth": "$auth_pwd",
  "tls": {
    "sni": "$hy_domain",
    "insecure": true
  },
  "quic": {
    "initStreamReceiveWindow": 16777216,
    "maxStreamReceiveWindow": 16777216,
    "initConnReceiveWindow": 33554432,
    "maxConnReceiveWindow": 33554432
  },
  "socks5": {
    "listen": "127.0.0.1:5080"
  },
  "transport": {
    "udp": {
      "hopInterval": "30s"
    }
  }
}
EOF
    # Generate SURGE configuration file
    cat << EOF > /root/hy/surge-hysteria.conf
    [Proxy]
    Hysteria = hysteria, $hy_domain, $last_port, password=$auth_pwd, sni=$domain, obfs=http, obfs-host=$domain, download-bandwidth=100
    EOF

    url="hysteria2://$auth_pwd@$last_ip:$last_port/?insecure=1&sni=$hy_domain#Misaka-Hysteria2"
    echo $url > /root/hy/url.txt

    systemctl daemon-reload
    systemctl enable hysteria-server
    systemctl start hysteria-server
    if systemctl is-active --quiet hysteria-server && [[ -f '/etc/hysteria/config.yaml' ]]; then
        green "HYSTERIA 2 SERVICE STARTED SUCCESSFULLY."
    else
        red "HYSTERIA 2 SERVICE FAILED TO START. PLEASE RUN 'systemctl status hysteria-server' TO CHECK SERVICE STATUS." && exit 1
    fi

    showconf
}

unst_hyv2(){
    systemctl stop hysteria-server.service >/dev/null 2>&1
    systemctl disable hysteria-server.service >/dev/null 2>&1
    rm -f /lib/systemd/system/hysteria-server.service /lib/systemd/system/hysteria-server@.service
    rm -rf /usr/local/bin/hysteria /etc/hysteria /root/hy /root/hysteria.sh
    iptables -t nat -F PREROUTING >/dev/null 2>&1
    netfilter-persistent save >/dev/null 2>&1
    green "HYSTERIA 2 HAS BEEN COMPLETELY UNINSTALLED!"
}

starthysteria(){
    systemctl start hysteria-server
    systemctl enable hysteria-server >/dev/null 2>&1
}

stophysteria(){
    systemctl stop hysteria-server
    systemctl disable hysteria-server >/dev/null 2>&1
}

hy_switch(){
    yellow "PLEASE SELECT THE OPERATION YOU NEED:"
    echo ""
    echo -e " ${GREEN}1.${PLAIN} START HYSTERIA 2"
    echo -e " ${GREEN}2.${PLAIN} STOP HYSTERIA 2"
    echo -e " ${GREEN}3.${PLAIN} RESTART HYSTERIA 2"
    echo ""
    read -rp "PLEASE ENTER OPTION [0-3]: " switchInput
    case $switchInput in
        1 ) starthysteria ;;
        2 ) stophysteria ;;
        3 ) restart_hysteria ;;
        * ) exit 1 ;;
    esac
}

replace_hysteria() {
    local file=$1
    local old=$2
    local new=$3
    sed -i "s#$old#$new#g" $file
}

restart_hysteria() {
    stophysteria && starthysteria
}

changeport(){
    if [[ -f "/etc/hysteria/config.yaml" ]]; then
        oldport=$(cat /etc/hysteria/config.yaml 2>/dev/null | sed -n 1p | awk '{print $2}' | awk -F ":" '{print $2}')
    
        inst_port && inst_jump

        if [[ -n $firstport ]]; then
            last_port="$port,$firstport-$endport"
        else
            last_port=$port
        fi

        replace_hysteria "/etc/hysteria/config.yaml" $oldport $port
        replace_hysteria "/root/hy/hy-client.yaml" $oldport $last_port
        replace_hysteria "/root/hy/hy-client.json" $oldport $last_port
        replace_hysteria "/root/hy/url.txt" $oldport $last_port

        restart_hysteria

        green "HYSTERIA 2 PORT SUCCESSFULLY CHANGED TO: $port"
        yellow "PLEASE MANUALLY UPDATE CLIENT CONFIGURATION FILE TO USE NODE"
        showconf
    fi
}

changepasswd(){
    if [[ -f "/etc/hysteria/config.yaml" ]]; then
        old_pwd=$(cat /etc/hysteria/config.yaml 2>/dev/null | sed -n 15p | awk '{print $2}')

        inst_pwd

        replace_hysteria "/etc/hysteria/config.yaml" $old_pwd $auth_pwd
        replace_hysteria "/root/hy/hy-client.yaml" $old_pwd $auth_pwd
        replace_hysteria "/root/hy/hy-client.json" $old_pwd $auth_pwd
        replace_hysteria "/root/hy/url.txt" $old_pwd $auth_pwd

        restart_hysteria

        green "HYSTERIA 2 NODE PASSWORD SUCCESSFULLY CHANGED TO: $auth_pwd"
        yellow "PLEASE MANUALLY UPDATE CLIENT CONFIGURATION FILE TO USE NODE"
        showconf
    fi
}

change_cert(){
    if [[ -f "/etc/hysteria/config.yaml" ]]; then
        old_cert=$(cat /etc/hysteria/config.yaml | grep cert | awk -F " " '{print $2}')
        old_key=$(cat /etc/hysteria/config.yaml | grep key | awk -F " " '{print $2}')
        old_hydomain=$(cat /root/hy/hy-client.yaml | grep sni | awk '{print $2}')

        inst_cert

        sed -i "s!$old_cert!$cert_path!g" /etc/hysteria/config.yaml
        sed -i "s!$old_key!$key_path!g" /etc/hysteria/config.yaml
        sed -i "6s/$old_hydomain/$hy_domain/g" /root/hy/hy-client.yaml
        sed -i "5s/$old_hydomain/$hy_domain/g" /root/hy/hy-client.json
        sed -i "s/$old_hydomain/$hy_domain/g" /root/hy/url.txt

        stophysteria && starthysteria

        green "HYSTERIA 2 NODE CERTIFICATE TYPE SUCCESSFULLY CHANGED"
        yellow "PLEASE MANUALLY UPDATE CLIENT CONFIGURATION FILE TO USE NODE"
        showconf
    fi
}

changeproxysite(){
    oldproxysite=$(cat /etc/hysteria/config.yaml | grep url | awk -F " " '{print $2}' | awk -F "https://" '{print $2}')
    
    inst_site

    sed -i "s#$oldproxysite#$proxysite#g" /etc/hysteria/config.yaml

    stophysteria && starthysteria

    green "HYSTERIA 2 NODE PROXY SITE SUCCESSFULLY CHANGED TO: $proxysite"
}

changeconf(){
    if [[ -f "/etc/hysteria/config.yaml" ]]; then
        green "HYSTERIA 2 CONFIGURATION OPTIONS:"
        echo -e " ${GREEN}1.${PLAIN} CHANGE PORT"
        echo -e " ${GREEN}2.${PLAIN} CHANGE PASSWORD"
        echo -e " ${GREEN}3.${PLAIN} CHANGE CERTIFICATE TYPE"
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
    fi
}

showconf(){
    if [[ -f "/etc/hysteria/config.yaml" ]]; then
        yellow "SURGE node information is as follows, and saved to /root/hy/surge-hysteria.conf"
        red "$(cat /root/hy/surge-hysteria.conf)"
        yellow "Hysteria 2 node share link is as follows, and saved to /root/hy/url.txt"
        red "$(cat /root/hy/url.txt)"
    fi
}

menu() {
    clear "
    echo -e "     ${LIGHT_RED}HYSTERIA II${PLAIN}"
    echo ""
    echo -e "${LIGHT_BLUE}AT WHAT SPEED MUST I LIVE, TO BE ABLE TO SEE YOU AGAIN?${PLAIN}"                      
    echo ""
    echo " -------------"
    echo -e " ${GREEN}3.${PLAIN} INSTALL${PLAIN}"
    echo -e " ${GREEN}4.${PLAIN} ${LIGHT_RED}UNINSTALL${PLAIN}"
    echo " -------------"
    echo -e " ${GREEN}5.${PLAIN} STOP, START, RESTART"
    echo -e " ${GREEN}6.${PLAIN} MODIF CONFIG"
    echo -e " ${GREEN}7.${PLAIN} DISPLAY CONFIG"
    echo " -------------"
    echo -e " ${GREEN}0.${PLAIN} EXIT"
    echo ""
    read -rp "Please enter an option [0-7]: " menuInput
    case $menuInput in
        3 ) inst_hyv2 ;;
        4 ) unst_hyv2 ;;
        5 ) control_hy ;;
        6 ) changeconf ;;
        7 ) showconf ;;
        * ) exit 1 ;;
    esac
}

menu