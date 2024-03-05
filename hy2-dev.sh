#!/bin/bash

# Define color codes
red='\e[31m'
green='\e[92m'
yellow='\e[33m'
reset='\e[0m'
underline='\e[4m'
blink='\e[5m'
cyan='\e[96m'
purple='\e[35m'

# Color print functions, corrected to use 'reset' instead of 'none'
_red() { echo -e "${red}$@${reset}"; }
_green() { echo -e "${green}$@${reset}"; }
_yellow() { echo -e "${yellow}$@${reset}"; }
_cyan() { echo -e "${cyan}$@${reset}"; }
_magenta() { echo -e "${purple}$@${reset}"; } # Corrected to use 'purple'
_red_bg() { echo -e "\e[41m$@${reset}"; }

is_err=$(_red_bg "ERROR!")
is_warn=$(_red_bg "WARNING!")

# Corrected the use of 'exit' in the error handling function
err() {
    echo -e "\n$is_err $@\n" && return 1
}

warn() {
    echo -e "\n$is_warn $@\n"
}


# Function to display messages with corrected '-e' option for echo
msg() {
    timestamp=$(TZ=Asia/Shanghai date "+%Y.%m.%d-%H:%M:%S")
    case $1 in
        err) echo -e "${red}[error | ${reset}${purple}${timestamp}${reset}${red}] $2${reset}" ;;
        warn) echo -e "${yellow}[warning | ${reset}${purple}${timestamp}${reset}${yellow}] $2${reset}" ;;
        ok) echo -e "${green}[success | ${reset}${purple}${timestamp}${reset}${green}] $2${reset}" ;;
        info) echo -e "[info | ${reset}${purple}${timestamp}${reset}] $2${reset}" ;;
        *) echo -e "[log | ${reset}${purple}${timestamp}${reset}] $2${reset}" ;;
    esac
}


random_color() {
  colors=("31" "32" "33" "34" "35" "36" "37")
  echo -e "\e[${colors[$((RANDOM % 7))]}m$1\e[0m"
}

# Check for root privileges and system compatibility
setup_environment() {
    if [[ $EUID -ne 0 ]]; then
        msg err "Root clearance required."
        return 1 # Use return instead of exit
    fi
    if ! type -P apt-get &>/dev/null && ! type -P yum &>/dev/null; then
        msg err "Unsupported package manager. This script only supports apt-get (Debian/Ubuntu) and yum (CentOS/RHEL)."
        return 1
    fi
    if [[ -z $(type -P systemctl) ]]; then
        msg err "Systemd is required."
        return 1
    fi
}

fullchain="/root/cert/fullchain.pem"
privatekey="/root/cert/private.key"
workspace="/etc/hysteria"
service="/etc/systemd/system/hysteria.service"
config="$workspace/config.json"

# Install missing packages
install_dependencies() {
    _yellow "Checking and installing missing dependencies..."
    local dependencies=("wget" "unzip" "jq" "net-tools" "socat" "curl" "cron" "dnsutils")
    if command -v apt-get &>/dev/null; then
        apt-get update -y
        apt-get install -y dnsutils ${dependencies[@]}
    elif command -v yum &>/dev/null; then
        yum makecache fast
        yum install -y bind-utils ${dependencies[@]}
    else
        msg err "Unsupported package manager. Script supports apt-get (Debian/Ubuntu) and yum (CentOS/RHEL)."
        exit 1
    fi
}

# Function to get the public IP of the server
get_ip() {
    ipv4=$(curl -s4 https://api.ipify.org)
    ipv6=$(curl -s6 https://api6.ipify.org)
}

# Verify domain is pointing to the server's IP
check_domain() {
    local domain=$1
    get_ip
    local domain_ips_v4=$(dig +short A $domain @1.1.1.1)
    local domain_ips_v6=$(dig +short AAAA $domain @1.1.1.1)
    final_ip="" # Initialize final_ip as an empty string

    if [[ $domain_ips_v4 =~ $ipv4 ]]; then
        final_ip=$ipv4
        msg ok "Domain $domain correctly resolves to this server IPv4: $ipv4."
    elif [[ $domain_ips_v6 =~ $ipv6 ]]; then
        final_ip=$ipv6
        msg ok "Domain $domain correctly resolves to this server IPv6: $ipv6."
    else
        msg err "Domain $domain does not resolve to this server IP."
        exit 1
    fi
    if [[ -n $final_ip ]]; then
        echo "Matched: $final_ip"
    fi
}


# Corrected 'is_port_used' function to properly check port usage
is_port_used() {
    local port=$1
    if ss -tuln | grep -q ":${port} "; then
        return 0 # Port is used
    else
        return 1 # Port is not used
    fi
}

# Generate a random password
generate_random_password() {
    local length=${1:-16} # Default length 16 if not specified
    echo $(tr -dc 'A-Za-z0-9' < /dev/urandom | head -c ${length})
}

# Function to check if a port is already in use
find_unused_port() {
    local port=$(shuf -i 1024-65535 -n 1)
    while ss -tuln | grep -q ":${port} "; do
        port=$(shuf -i 1024-65535 -n 1)
    done
    echo $port
}

check_cert() {
    local domain=$1
    if ~/.acme.sh/acme.sh --list | grep -q $domain; then
        read -rp "A certificate for $domain already exists. Do you want to revoke it? [y/N]: " revoke
        if [[ "$revoke" =~ ^[Yy]$ ]]; then
            echo "Revoking the certificate for $domain..."
            ~/.acme.sh/acme.sh --revoke -d $domain --ecc
            ~/.acme.sh/acme.sh --remove -d $domain --ecc
            apply_cert $domain "force"
        else
            echo "Using the existing certificate for $domain."
            update_cert $domain
        fi
    else
        apply_cert $domain
    fi
}

apply_cert() {
    local domain=$1
    local method=${2:-"acme"} # 默认使用ACME方法
    local cert_dir="/root/cert/$domain" # 为每个域名指定一个证书存储目录
    
    mkdir -p "$cert_dir" # 创建证书存储目录

    if [[ "$method" == "acme" ]]; then
        echo "Applying for an ACME certificate for $domain..."
        if [ ! -f "/root/.acme.sh/acme.sh" ]; then
            echo "Installing acme.sh..."
            curl https://get.acme.sh | sh
        fi
        ~/.acme.sh/acme.sh --issue --force --ecc --standalone -d $domain --keylength ec-256 --server letsencrypt
        ~/.acme.sh/acme.sh --install-cert -d $domain --ecc \
            --fullchain-file "$cert_dir/fullchain.pem" \
            --key-file "$cert_dir/private.key"
        echo "ACME certificate applied for $domain."
    elif [[ "$method" == "openssl" ]]; then
        echo "Generating an OpenSSL certificate for $domain..."
        openssl req -newkey rsa:2048 -nodes -keyout "$cert_dir/private.key" \
            -x509 -days 365 -out "$cert_dir/fullchain.pem" -subj "/CN=$domain"
        echo "OpenSSL certificate generated for $domain."
    fi

    # 更新证书路径变量
    fullchain="$cert_dir/fullchain.pem"
    privatekey="$cert_dir/private.key"
    echo "Certificate path: $fullchain"
    echo "Key path: $privatekey"
}

update_cert() {
    local domain=$1
    echo "Setting up auto-renewal for $domain's certificate..."
    ~/.acme.sh/acme.sh --cron --domain $domain
    crontab -l | grep -q "$domain" && echo "Auto-renewal job for $domain's certificate already exists." ||
    { crontab -l > conf_temp; echo "0 0 * */2 * ~/.acme.sh/acme.sh --cron --domain $domain" >> conf_temp; crontab conf_temp; rm conf_temp; echo "Added auto-renewal job for $domain's certificate."; }
}

del_cert() {
    local domain=$1
    # 删除ACME.sh中的证书记录
    ~/.acme.sh/acme.sh --remove -d $domain --ecc
    # 删除证书文件
    rm -f /root/cert/$domain/*
    echo "Certificate for $domain removed."
}

create_systemd() {
    cat > $service << EOF
[Unit]
Description=Hysteria is a feature-packed proxy & relay tool optimized for lossy, unstable connections
Documentation=https://github.com/HyNetwork/hysteria
After=network.target

[Service]
User=root
WorkingDirectory=$workspace
ExecStart=/usr/local/bin/hysteria -c $config
Restart=on-failure
RestartPreventExitStatus=23

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable hysteria
    msg ok "Systemd service created."
}


# Configuration creation including domain, port, password, and masquerade site
create_config() {
    read -rp "Drop your domain name here: " domain
    check_domain "$domain"

    local port=$(find_unused_port)
    local auth_password=$(generate_random_password 16)
    local proxy_site="www.example.com"

    cat <<EOF > $config
{
  "listen": ":$port",
  "tls": {
    "cert": "$fullchain",
    "key": "$privatekey"
  },
  "auth": {
    "type": "password",
    "password": "$auth_password"
  },
  "obfs": "$proxy_site"
}
EOF

    msg ok "Configuration created successfully."
    cat > "$workspace/proxy_surge.ini" << EOF
    Proxy-HY = hysteria, $domain, $port, password=$auth_password, sni=$proxy_site
EOF
}


# Hysteria installation, uninstallation, and management functions
install() {
    if [[ -e "$service" ]]; then
        read -rp "Reinstall? (y/n): " input
        case "$input" in
            y|Y) uninstall ;;
            *) menu ;;
        esac
    else
        install_dependencies
    fi

    msg info "Installing Hysteria..."
    bash <(curl -fsSL https://get.hy2.com) && msg ok "Hysteria installed." || {
        msg err "Hysteria installation failed."
        exit 1
    }

    mkdir -p "$workspace"
    check_cert "$domain"

    create_systemd
    create_config

    boot
    msg ok "Hysteria deployed successfully."
    msg ok "------------------------ FOR SURGE USE ONLY ------------------------\n"
    cat "${workspace}/proxy_surge.ini"
    echo ""
    echo "----------------------------------------------------------------------------\n"
}



uninstall(){
    systemctl stop hysteria.service >/dev/null 2>&1
    systemctl disable hysteria.service >/dev/null 2>&1
    rm -f $service
    rm -rf /usr/local/bin/hysteria $workspace
    _green "Uninstalled successfully"
}

boot() {
    systemctl start hysteria.service
    sleep 2
    if systemctl is-active --quiet hysteria.service; then
        msg ok "Hysteria started successfully."
    else
        msg err "Hysteria failed to start."
        systemctl status hysteria.service
        return 1
    fi  
}

stop() {
    systemctl stop hysteria
    msg ok "Hysteria has been stopped."
}

reboot() {
    stop
    sleep 2
    boot
}

#// switch(){
#//     random_color "Perhaps rain comes."
#//     random_color "If so, will you stay here with me?"
#//     echo ""
#//     echo -e " ${GREEN}1.${PLAIN} Start"
#//     echo -e " ${GREEN}2.${PLAIN} Shutdown"
#//     echo -e " ${GREEN}3.${PLAIN} Restart"
#//     echo ""
#//     read -rp "Option [0-3]: " switchInput
#//     case $switchInput in
#//         1 ) boot ;;
#//         2 ) stop ;;
#//         3 ) stop && boot ;;
#//         * ) exit 1 ;;
#//     esac
#// }


changeconfig() {
    local key=$1
    local newValue=$2
    local configFile="/etc/hysteria/config.json"

    echo "Updating $key to $newValue in the config file."
    
    jq ".$key = \"$newValue\"" $configFile > /tmp/config.json && mv /tmp/config.json $configFile

    echo "$key updated successfully."
    systemctl restart hysteria
}

#// update_core(){
#//     # ReInstall Hysteria 2
#//     bash <(curl -fsSL https://get.hy2.sh/)
#// }


# Manage Hysteria service (start, stop, restart)
manage() {
    _green "1. Boot"
    _red "2. Stop" 
    _yellow "3. Reboot"
    echo "4. Modify Config"
    echo "5. View Config"
    echo "6. Back to Main Menu"
    read -p "Select operation (1-5): " operation

    case $operation in
        1) boot ;;
        2) stop ;;
        3) reboot ;;
        4) modify ;;
        5) checkconfig ;;
        6) menu ;;
        *) msg err "Invalid operation." ;;
    esac
}

# 修改配置的函数
modify() {
    echo "Select configuration to modify:"
    echo "1. Port"
    echo "2. Password"
    echo "3. Masquerade Site"
    echo "4. Certificate"
    echo "5. Display Configuration"
    echo "6. Return to Main Menu"
    read -rp "Select an option: " choice

    case $choice in
        1)
            read -rp "Enter new port: " newPort
            changeconfig "listen" ":$newPort"
            ;;
        2)
            read -rp "Enter new password: " newPassword
            changeconfig "auth.password" "$newPassword"
            ;;
        3)
            read -rp "Enter new masquerade site (e.g., www.example.com): " newSite
            changeconfig "obfs" "$newSite"
            ;;
        4)
            changecert
            ;;
        5)
            checkconfig
            ;;
        6)
            menu
            ;;
        *)
            echo "Invalid option. Please try again."
            modify
            ;;
    esac
}

checkconfig() {
    if [[ -f "$config" ]]; then
        cat "$config"
    else
        msg err "Configuration file not found."
    fi
}

changecert() {
    echo "Changing SSL/TLS Certificate for Hysteria"
    echo "1. Apply New Certificate"
    echo "2. Revoke Current Certificate"
    echo "3. Update Certificate (Renewal)"
    echo "4. Return to Main Menu"
    read -rp "Select an option: " choice

    case $choice in
        1)
            read -rp "Enter domain for the new certificate: " domain
            apply_cert "$domain" "acme"
            echo "New certificate applied. Hysteria needs to be restarted."
            ;;
        2)
            read -rp "Enter domain of the certificate to revoke: " domain
            ~/.acme.sh/acme.sh --revoke -d $domain --ecc
            echo "Certificate revoked. Consider applying a new one."
            ;;
        3)
            read -rp "Enter domain of the certificate to update: " domain
            update_cert "$domain"
            echo "Certificate renewal setup updated."
            ;;
        4)
            menu
            ;;
        *)
            echo "Invalid option. Please try again."
            changecert
            ;;
    esac
}


menu() {
    clear
    echo -e "${cyan}Hysteria 2${reset}"
    echo "----------------------------------------------------------------------------------"
    echo -e "${cyan}At what speed must I live, to be able to see you again?${reset}"
    echo "----------------------------------------------------------------------------------"
    echo -e " ${green}1.${reset} Install"
    echo -e " ${red}2.${reset} Uninstall"
    echo -e " ${yellow}3.${reset} Manage"
    echo -e " ${purple}0.${reset} Exit"
    echo ""
    read -rp "Option [0-3]: " menuInput
    case $menuInput in
        1) install ;;
        2) uninstall ;;
        3) manage ;;
        0) exit 0 ;;
        *) 
            echo "Invalid option. Please try again."
            menu ;;
    esac
}

menu
