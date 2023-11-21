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

# Define system and installation methods
REGEX=("debian" "ubuntu" "centos|red hat|kernel|oracle linux|alma|rocky" "'amazon linux'" "fedora")
RELEASE=("Debian" "Ubuntu" "CentOS" "CentOS" "Fedora")
PACKAGE_MANAGER=("apt" "apt" "yum" "yum" "yum")

[[ $EUID -ne 0 ]] && red "NOTE: PLEASE RUN THE SCRIPT AS ROOT USER" && exit 1

# Determine the system
CMD=("$(grep -i pretty_name /etc/os-release 2>/dev/null | cut -d \" -f2)" "$(hostnamectl 2>/dev/null | grep -i system | cut -d : -f2)" "$(lsb_release -sd 2>/dev/null)" "$(grep -i description /etc/lsb-release 2>/dev/null | cut -d \" -f2)" "$(grep . /etc/redhat-release 2>/dev/null)" "$(grep . /etc/issue 2>/dev/null | cut -d \\ -f1 | sed '/^[ ]*$/d')")

for i in "${CMD[@]}"; do
    SYS="$i" && [[ -n $SYS ]] && break
done

for ((int = 0; int < ${#REGEX[@]}; int++)); do
    [[ $(echo "$SYS" | tr '[:upper:]' '[:lower:]') =~ ${REGEX[int]} ]] && SYSTEM="${RELEASE[int]}" && [[ -n $SYSTEM ]] && break
done

[[ -z $SYSTEM ]] && red "CURRENTLY YOUR VPS OPERATING SYSTEM IS NOT SUPPORTED!" && exit 1

# Install curl if not present
if [[ -z $(type -P curl) ]]; then
    [[ $SYSTEM != "CentOS" ]] && ${PACKAGE_MANAGER[int]} update
    ${PACKAGE_MANAGER[int]} -y install curl
fi

# Update packages and install necessary ones
if [[ $SYSTEM != "CentOS" ]]; then
    ${PACKAGE_MANAGER[int]} update
fi
${PACKAGE_MANAGER[int]} -y install wget sudo qrencode procps iptables-persistent netfilter-persistent

realip(){
    ip=$(curl -s4m8 ip.sb -k) || ip=$(curl -s6m8 ip.sb -k)
}

inst_cert(){
    green "SELECT HYSTERIA CERTIFICATE APPLICATION METHOD:"
    echo ""
    echo -e " ${GREEN}1.${PLAIN} SELF-SIGNED CERTIFICATE ${YELLOW}(DEFAULT)${PLAIN}"
    echo -e " ${GREEN}2.${PLAIN} ACME SCRIPT AUTO-APPLICATION"
    echo -e " ${GREEN}3.${PLAIN} CUSTOM CERTIFICATE PATH"
    echo ""
    read -rp "ENTER OPTION [1-3]: " certInput
    if [[ $certInput == 2 ]]; then
        cert_path="/root/cert.crt"
        key_path="/root/private.key"

        chmod a+x /root # 让 Hysteria 主程序访问到 /root 目录

        if [[ -f /root/cert.crt && -f /root/private.key ]] && [[ -s /root/cert.crt && -s /root/private.key ]] && [[ -f /root/ca.log ]]; then
            domain=$(cat /root/ca.log)
            green "EXISTING CERTIFICATE FOR DOMAIN: $domain FOUND, APPLYING"
            hy_domain=$domain
        else
            wget -N https://gitlab.com/Misaka-blog/acme-script/-/raw/main/acme.sh && bash acme.sh
            
            if [[ -f /root/cert.crt && -f /root/private.key ]] && [[ -s /root/cert.crt && -s /root/private.key ]] && [[ -f /root/ca.log ]]; then
                domain=$(cat /root/ca.log)
                hy_domain=$domain
            else
                red "CERTIFICATE APPLICATION FAILED, EXITING SCRIPT" && exit
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
        green "USING SELF-SIGNED CERTIFICATE AS HYSTERIA NODE CERTIFICATE"

        read -rp "ENTER HYSTERIA SELF-SIGNED CERTIFICATE ADDRESS (REMOVE HTTPS://) [PRESS ENTER FOR DEFAULT BING]: " certsite
        [[ -z $certsite ]] && certsite="www.bing.com"
        yellow "USING HYSTERIA SELF-SIGNED CERTIFICATE ADDRESS: $certsite"

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

        cert_path="/etc/hysteria/cert.crt"
        key_path="/etc/hysteria/private.key"

        openssl ecparam -genkey -name prime256v1 -out /etc/hysteria/private.key
        openssl req -new -x509 -days 36500 -key /etc/hysteria/private.key -out /etc/hysteria/cert.crt -subj "/CN=$certsite"

        chmod 777 /etc/hysteria/cert.crt
        chmod 777 /etc/hysteria/private.key

        hy_domain="$certsite"
        domain="$certsite"
    fi
}

inst_port(){
    iptables -t nat -F PREROUTING >/dev/null 2>&1

    read -p "SET HYSTERIA PORT [1-65535] (PRESS ENTER TO RANDOMLY ASSIGN PORT): " port
    [[ -z $port ]] && port=$(shuf -i 2000-65535 -n 1)
    until [[ -z $(ss -tunlp | grep -w udp | awk '{print $5}' | sed 's/.*://g' | grep -w "$port") ]]; do
        if [[ -n $(ss -tunlp | grep -w udp | awk '{print $5}' | sed 's/.*://g' | grep -w "$port") ]]; then
            echo "PORT $port IS ALREADY IN USE BY ANOTHER PROGRAM, PLEASE CHANGE PORT AND TRY AGAIN!"
            read -p "SET HYSTERIA PORT [1-65535] (PRESS ENTER TO RANDOMLY ASSIGN PORT): " port
            [[ -z $port ]] && port=$(shuf -i 2000-65535 -n 1)
        fi
    done

    yellow "PORT FOR HYSTERIA NODE SET TO: $port"
}

inst_jump(){
    echo "SELECT HYSTERIA PORT MODE:"
    echo ""
    echo " 1. SINGLE PORT (DEFAULT)"
    echo " 2. PORT JUMPING"
    echo ""
    read -rp "ENTER OPTION [1-2]: " jumpInput
    if [[ $jumpInput == 2 ]]; then
        read -p "SET START PORT FOR RANGE (RECOMMENDED BETWEEN 10000-65535): " firstport
        read -p "SET END PORT FOR RANGE (RECOMMENDED BETWEEN 10000-65535, MUST BE GREATER THAN START PORT): " endport
        if [[ $firstport -ge $endport ]]; then
            until [[ $firstport -le $endport ]]; do
                if [[ $firstport -ge $endport ]]; then
                    echo "START PORT IS LESS THAN END PORT, PLEASE RE-ENTER START AND END PORTS"
                    read -p "SET START PORT FOR RANGE (RECOMMENDED BETWEEN 10000-65535): " firstport
                    read -p "SET END PORT FOR RANGE (RECOMMENDED BETWEEN 10000-65535, MUST BE GREATER THAN START PORT): " endport
                fi
            done
        fi
        iptables -t nat -A PREROUTING -p udp --dport $firstport:$endport  -j DNAT --to-destination :$port
        ip6tables -t nat -A PREROUTING -p udp --dport $firstport:$endport  -j DNAT --to-destination :$port
        netfilter-persistent save >/dev/null 2>&1
    else
        echo "CONTINUING WITH SINGLE PORT MODE"
    fi
}

inst_pwd(){
    read -p "SET HYSTERIA PASSWORD (PRESS ENTER TO USE RANDOM CHARACTERS): " auth_pwd
    [[ -z $auth_pwd ]] && auth_pwd=$(date +%s%N | md5sum | cut -c 1-8)
    echo "PASSWORD FOR HYSTERIA NODE SET TO: $auth_pwd"
}

inst_site(){
    read -rp "ENTER HYSTERIA 2 MASQUERADE SITE URL (WITHOUT HTTPS://) [PRESS ENTER FOR DEFAULT 'maimai.sega.jp']: " proxysite
    [[ -z $proxysite ]] && proxysite="maimai.sega.jp"
    echo "MASQUERADE SITE FOR HYSTERIA 2 NODE SET TO: $proxysite"
}

inst_hyv2(){

    if [[ -f "/usr/local/bin/hysteria" ]]; then
        echo "HYSTERIA 2 INSTALLED"
    else
        echo "HYSTERIA 2 INSTALLATION FAILED, PLEASE RERUN SCRIPT" && exit 1
    fi

    # 询问用户 Hysteria 配置
    inst_cert
    inst_port
    inst_jump
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

    url="hysteria2://$auth_pwd@$last_ip:$last_port/?insecure=1&sni=$hy_domain"
    echo $url > /root/hy/url.txt

    surge_format="TEST-HY2 = hysteria2, $last_ip, $last_port, password=$auth_pwd, sni=$hy_domain, download-bandwidth=1000"
    echo $surge_format > /root/hy/surge-node.conf

    systemctl daemon-reload
    systemctl enable hysteria-server
    systemctl start hysteria-server
    if [[ -n $(systemctl status hysteria-server 2>/dev/null | grep -w active) && -f '/etc/hysteria/config.yaml' ]]; then
        echo "HYSTERIA 2 SERVICE STARTED SUCCESSFULLY"
    else
        echo "HYSTERIA 2 SERVICE FAILED TO START, PLEASE RUN 'systemctl status hysteria-server' TO CHECK SERVICE STATUS AND PROVIDE FEEDBACK" && exit 1
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
    green "Hysteria 2 已彻底卸载完成！"
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
    yellow "请选择你需要的操作："
    echo ""
    echo -e " ${GREEN}1.${PLAIN} 启动 Hysteria 2"
    echo -e " ${GREEN}2.${PLAIN} 关闭 Hysteria 2"
    echo -e " ${GREEN}3.${PLAIN} 重启 Hysteria 2"
    echo ""
    read -rp "请输入选项 [0-3]: " switchInput
    case $switchInput in
        1 ) starthysteria ;;
        2 ) stophysteria ;;
        3 ) stophysteria && starthysteria ;;
        * ) exit 1 ;;
    esac
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

        sed -i "1s#$oldport#$port#g" /etc/hysteria/config.yaml
        sed -i "1s#$oldport#$last_port#g" /root/hy/url.txt
        sed -i "1s#$oldport#$last_port#g" /root/hy/surge-node.conf
        
        stophysteria && starthysteria

        green "NEW PORT: $port"
        yellow "PLEASE MANUALLY UPDATE THE CLIENT CONFIGURATION FILE TO USE THE NODE"
        showconf
    fi
}

changepasswd(){
    if [[ -f "/etc/hysteria/config.yaml" ]]; then
        old_pwd=$(cat /etc/hysteria/config.yaml 2>/dev/null | sed -n 15p | awk '{print $2}')

        inst_pwd

        sed -i "1s#$old_pwd#$auth_pwd#g" /etc/hysteria/config.yaml
        sed -i "s/$old_pwd/$auth_pwd/g" /root/hy/url.txt
        sed -i "1s#$old_pwd#$auth_pwd#g" /root/hy/surge-node.conf

        stophysteria && starthysteria

        green "NEW PASSWORD: $auth_pwd"
        yellow "PLEASE MANUALLY UPDATE THE CLIENT CONFIGURATION FILE TO USE THE NODE"
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
        sed -i "s/$old_hydomain/$hy_domain/g" /root/hy/surge-node.conf
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
        yellow "HYSTERIA 2 NODE FOR SURGE SAVED TO /root/hy/surge-node.conf"
        red "$(cat /root/hy/surge-node.conf)"
        yellow "HYSTERIA 2 NODE SHARE LINK SAVED TO /root/hy/url.txt"
        red "$(cat /root/hy/url.txt)"
    fi
}

menu() {
    clear
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