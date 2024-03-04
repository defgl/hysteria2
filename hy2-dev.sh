#!/bin/bash

export LANG=en_US.UTF-8

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
    [[ $EUID -ne 0 ]] && msg err "Root clearance required." && exit 1
    cmd=$(type -P apt-get || type -P yum) || msg err "Unsupported package manager. This script only supports apt-get (Debian/Ubuntu) and yum (CentOS/RHEL)." && exit 1
    [[ ! $(type -P systemctl) ]] && msg err "Systemd is required." && exit 1
}

fullchain="/root/cert/fullchain.pem"
privatekey="/root/cert/private.key"
config="/etc/hysteria/config.json"
hysteria_service="hysteria-server"

# Install missing packages
install_dependencies() {
    msg info "Checking and installing missing dependencies..."
    local dependencies=("wget" "unzip" "jq" "net-tools" "socat" "curl" "cron" "dnsutils" "bind-utils")
    for pkg in "${dependencies[@]}"; do
        if ! command -v $pkg &>/dev/null; then
            msg info "Installing $pkg..."
            sudo $cmd install -y $pkg
        else
            msg info "$pkg is already installed."
        fi
    done
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

    if [[ $domain_ips_v4 =~ $ipv4 ]] || [[ $domain_ips_v6 =~ $ipv6 ]]; then
        msg ok "Domain $domain correctly resolves to this server IP."
    else
        msg err "Domain $domain does not resolve to this server IP."
        exit 1
    fi
}

# Corrected 'is_port_used' function to properly check port usage
is_port_used() {
    if [[ $(type -P netstat) ]]; then
        is_used_port="$(netstat -tunlp | awk '/^tcp/ {print $4}' | cut -d: -f2)"
    elif [[ $(type -P ss) ]]; then
        is_used_port="$(ss -tunlp | awk '/^tcp/ {print $5}' | cut -d: -f2)"
    else
        is_cant_test_port=1
        msg warn "Unable to check if the port is available."
        return 1 # Indicating failure to check port
    fi

    if echo "$is_used_port" | grep -qw "^${1}$"; then
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

# Configuration creation
# Configuration creation including domain, port, password, and masquerade site
create_config() {
    msg info "Configuring Hysteria..."
    read -rp "Enter your domain (Required for ACME certificate): " domain
    check_domain "$domain"
    cert_method="acme" # Default to ACME. "openssl" for OpenSSL certificates.
    apply_cert "$domain" "$cert_method"

    local port=$(find_unused_port)
    local auth_pwd=$(generate_random_password)
    local proxysite="www.example.com" # Default masquerade site

    cat <<EOF > /etc/hysteria/config.json
{
  "listen": ":$port",
  "tls": {
    "cert": "/root/cert/fullchain.pem",
    "key": "/root/cert/private.key"
  },
  "auth": {
    "type": "password",
    "password": "$auth_pwd"
  },
  "obfs": "$proxysite"
}
EOF
    msg ok "Configuration created successfully."
}




# Hysteria installation, uninstallation, and management functions
instal l() {
    setup_environment
    install_dependencies
    create_config

    # Install Hysteria 2
    bash <(curl -fsSL https://get.hy2.sh/)

    if [[ -f "/usr/local/bin/hysteria" ]]; then
        green "Installation successful."
    else
        red "Installation failed."
        exit 1
    fi



    fi

        fi
    fi

    mkdir /root/hy
    
    surge_format="NodeName = hysteria2, $last_ip, $last_port, password=$auth_pwd, sni=$hy_domain, download-bandwidth=1000, skip-cert-verify=true"
    echo $surge_format > /root/hy/proxy

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
    #cyan "Proxy is ready."
    #cyan "--- ___ ---"
    echo ""
    cyan " ^_^ ^_^"
    cyan "   ^_^  "
    echo ""
    cyan "$(cat /root/hy/proxy-surge.ini)"
}

uninstall(){
    systemctl stop hysteria-server.service >/dev/null 2>&1
    systemctl disable hysteria-server.service >/dev/null 2>&1
    rm -f /lib/systemd/system/hysteria-server.service /lib/systemd/system/hysteria-server@.service
    rm -rf /usr/local/bin/hysteria /etc/hysteria /root/hy /root/hysteria.sh
    iptables -t nat -F PREROUTING >/dev/null 2>&1
    netfilter-persistent save >/dev/null 2>&1

    green "Uninstalled successfully"
}

boot(){
    systemctl start hysteria-server
    systemctl enable hysteria-server >/dev/null 2>&1
}

stop(){
    systemctl stop hysteria-server
    systemctl disable hysteria-server >/dev/null 2>&1
}

switch(){
    random_color "Perhaps rain comes."
    random_color "If so, will you stay here with me?"
    echo ""
    echo -e " ${GREEN}1.${PLAIN} Start"
    echo -e " ${GREEN}2.${PLAIN} Shutdown"
    echo -e " ${GREEN}3.${PLAIN} Restart"
    echo ""
    read -rp "Option [0-3]: " switchInput
    case $switchInput in
        1 ) boot ;;
        2 ) stop ;;
        3 ) stop && boot ;;
        * ) exit 1 ;;
    esac
}


changeconfig() {
    local key=$1
    local newValue=$2
    local configFile="/etc/hysteria/config.json"

    echo "Updating $key to $newValue in the config file."
    
    # 使用jq工具修改JSON配置（确保已安装jq）
    jq ".$key = \"$newValue\"" $configFile > /tmp/config.json && mv /tmp/config.json $configFile

    echo "$key updated successfully."
    systemctl restart hysteria-server
}



#// update_core(){
#//     # ReInstall Hysteria 2
#//     bash <(curl -fsSL https://get.hy2.sh/)
#// }


# Manage Hysteria service (start, stop, restart)
manage() {
    echo "1. Boot"
    echo "2. Stop"
    echo "3. Reboot"
    echo "4. Config"
    echo "5. Menu"
    read -rp "Choose an option(1/2/3/4/5): " choice

    case $choice in
        1 ) boot ;;
        2 ) stop ;;
        3 ) stop && boot ;;
        4) modify ;;
        5) menu ;;
        *) msg err "Invalid option. Please choose again." && manage ;;
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
    if [[ -f "$config_file" ]]; then
        cat "$config_file"
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
    echo -e "${random_color}Hysteria 2${reset}"
    echo "----------------------------------------------------------------------------------"
    echo -e "${random_color}                At what speed must i live, to be able to see you again?${reset}"
    echo "----------------------------------------------------------------------------------"
    echo -e " ${green}1.${reset} Install"
    echo -e " ${red}2.${reset} Uninstall"
    echo ""
    echo -e " ${yellow}3.${reset} Mange"
    echo ""
    echo -e " ${purple}0.${reset} Exit"
    echo ""
    read -rp "Option [0-6]: " menuInput
    case $menuInput in
        1) install ;;
        2) uninstall ;;
        3) manage ;;
        0) exit 0 ;;
        *) 
            echo "Invalid option. Please try again."
            menu
            ;;
    esac
}


menu