#!/BIN/BASH

EXPORT lang=EN_us.utf-8

red="\033[31M"
green="\033[32M"
yellow="\033[33M"
plain="\033[0M"
# 颜色定义
blue="\033[34M"
purple="\033[35M"
cyan="\033[36M"
light_gray="\033[37M"
dark_gray="\033[90M"
light_red="\033[91M"
light_green="\033[92M"
light_yellow="\033[93M"
light_blue="\033[94M"
light_purple="\033[95M"
underline_purple="\E[4;35M"
light_cyan="\033[96M"
white="\033[97M"

# 相应的函数

RED(){
    ECHO -E "\033[31M\033[01M$1\033[0M"
}

GREEN(){
    ECHO -E "\033[32M\033[01M$1\033[0M"
}

YELLOW(){
    ECHO -E "\033[33M\033[01M$1\033[0M"
}

BLUE(){
    ECHO -E "${blue}\033[01M$1${plain}"
}

PURPLE(){
    ECHO -E "${purple}\033[01M$1${plain}"
}

CYAN(){
    ECHO -E "${cyan}\033[01M$1${plain}"
}

LIGHT_RED(){
    ECHO -E "${light_red}\033[01M$1${plain}"
}

LIGHT_GREEN(){
    ECHO -E "${light_green}\033[01M$1${plain}"
}

LIGHT_YELLOW(){
    ECHO -E "${light_yellow}\033[01M$1${plain}"
}

LIGHT_BLUE(){
    ECHO -E "${light_blue}\033[01M$1${plain}"
}

LIGHT_PURPLE(){
    ECHO -E "${light_purple}\033[01M$1${plain}"
}

LIGHT_CYAN(){
    ECHO -E "${light_cyan}\033[01M$1${plain}"
}

WHITE(){
    ECHO -E "${white}\033[01M$1${plain}"
}


# cHECK FOR ROOT PRIVILEGES
[[ $euid -NE 0 ]] && RED "please run as root" && EXIT 1

# sIMPLIFY os DETECTION
os_name=$(GREP -eO "(DEBIAN|UBUNTU|CENTOS|FEDORA|RED HAT|ORACLE LINUX|ALMA|ROCKY|AMAZON LINUX)" /ETC/OS-RELEASE | TR '[:UPPER:]' '[:LOWER:]' | HEAD -N 1)

# dEFINE PACKAGE MANAGEMENT COMMANDS BASED ON os
CASE "$os_name" IN
    DEBIAN|UBUNTU)
        package_manager_update="APT-GET UPDATE"
        package_manager_install="APT-GET INSTALL -Y"
        ;;
    CENTOS|RED\ HAT|ORACLE\ LINUX|ALMA|ROCKY)
        package_manager_update="YUM UPDATE -Y"
        package_manager_install="YUM INSTALL -Y"
        ;;
    FEDORA)
        package_manager_update="DNF UPDATE -Y"
        package_manager_install="DNF INSTALL -Y"
        ;;
    *)
        RED "unsupported os"
        EXIT 1
        ;;
ESAC

# uPDATE AND INSTALL REQUIRED PACKAGES
$package_manager_update
$package_manager_install CURL WGET SUDO QRENCODE PROCPS IPTABLES-PERSISTENT NETFILTER-PERSISTENT

# aDDITIONAL LOGIC IF NEEDED...

REALIP(){
    IP=$(CURL -S4M8 IP.SB -K) || IP=$(CURL -S6M8 IP.SB -K)
}

INST_CERT(){
    GREEN "请选择证书申请方式:"
    ECHO ""
    ECHO -E " ${green}1.${plain} 采用 acme 申请证书"
    ECHO -E " ${green}2.${plain} 采用oPENssl 的伪bING证书"
    ECHO -E " ${green}3.${plain} 自定义证书"
    ECHO ""
    READ -RP "oPTION [1-3]: " CERTiNPUT
    IF [[ $CERTiNPUT == 1 ]]; THEN
        CERT_PATH="/ROOT/CERT.CRT"
        KEY_PATH="/ROOT/PRIVATE.KEY"

        CHMOD -r 777 /ROOT # 让 hYSTERIA 主程序访问到 /ROOT 目录

        IF [[ -F /ROOT/CERT.CRT && -F /ROOT/PRIVATE.KEY ]] && [[ -S /ROOT/CERT.CRT && -S /ROOT/PRIVATE.KEY ]] && [[ -F /ROOT/CA.LOG ]]; THEN
            DOMAIN=$(CAT /ROOT/CA.LOG)
            GREEN "existing certificate detected for domain: $DOMAIN, applying"
            HY_DOMAIN=$DOMAIN
        ELSE
            warpV4sTATUS=$(CURL -S4M8 HTTPS://WWW.CLOUDFLARE.COM/CDN-CGI/TRACE -K | GREP WARP | CUT -D= -F2)
            warpV6sTATUS=$(CURL -S6M8 HTTPS://WWW.CLOUDFLARE.COM/CDN-CGI/TRACE -K | GREP WARP | CUT -D= -F2)
            IF [[ $warpV4sTATUS =~ ON|PLUS ]] || [[ $warpV6sTATUS =~ ON|PLUS ]]; THEN
                WG-QUICK DOWN WGCF >/DEV/NULL 2>&1
                SYSTEMCTL STOP WARP-GO >/DEV/NULL 2>&1
                REALIP
                WG-QUICK UP WGCF >/DEV/NULL 2>&1
                SYSTEMCTL START WARP-GO >/DEV/NULL 2>&1
            ELSE
                REALIP
            FI
            
            READ -P "domain for applying certificate:" DOMAIN
            [[ -Z $DOMAIN ]] && RED "invalid input, exiting script" && EXIT 1
            GREEN "cONFIRMED:$DOMAIN" && SLEEP 1
            DOMAINip=$(CURL -SM8 IPGET.NET/?IP="${DOMAIN}")
            IF [[ $DOMAINip == $IP ]]; THEN
                ${package_install[INT]} CURL WGET SUDO SOCAT OPENSSL
                IF [[ $system == "cENTos" ]]; THEN
                    ${package_install[INT]} CRONIE
                    SYSTEMCTL START CROND
                    SYSTEMCTL ENABLE CROND
                ELSE
                    ${package_install[INT]} CRON
                    SYSTEMCTL START CRON
                    SYSTEMCTL ENABLE CRON
                FI
                CURL HTTPS://GET.ACME.SH | SH -S EMAIL=$(DATE +%S%n | MD5SUM | CUT -C 1-16)@GMAIL.COM
                SOURCE ~/.BASHRC
                BASH ~/.ACME.SH/ACME.SH --UPGRADE --AUTO-UPGRADE
                BASH ~/.ACME.SH/ACME.SH --SET-DEFAULT-CA --SERVER LETSENCRYPT
                IF [[ -N $(ECHO $IP | GREP ":") ]]; THEN
                    BASH ~/.ACME.SH/ACME.SH --ISSUE -D ${DOMAIN} --STANDALONE -K EC-256 --LISTEN-V6 --INSECURE
                ELSE
                    BASH ~/.ACME.SH/ACME.SH --ISSUE -D ${DOMAIN} --STANDALONE -K EC-256 --INSECURE
                FI
                BASH ~/.ACME.SH/ACME.SH --INSTALL-CERT -D ${DOMAIN} --KEY-FILE /ROOT/PRIVATE.KEY --FULLCHAIN-FILE /ROOT/CERT.CRT --ECC
                IF [[ -F /ROOT/CERT.CRT && -F /ROOT/PRIVATE.KEY ]] && [[ -S /ROOT/CERT.CRT && -S /ROOT/PRIVATE.KEY ]]; THEN
                    ECHO $DOMAIN > /ROOT/CA.LOG
                    SED -I '/--CRON/D' /ETC/CRONTAB >/DEV/NULL 2>&1
                    ECHO "0 0 * * * ROOT BASH /ROOT/.ACME.SH/ACME.SH --CRON -F >/DEV/NULL 2>&1" >> /ETC/CRONTAB
                    GREEN "certificate application successful! certificate (CERT.CRT) and private key (PRIVATE.KEY) saved to /ROOT directory"
                    YELLOW "certificate crt file path: /ROOT/CERT.CRT"
                    YELLOW "private key file path: /ROOT/PRIVATE.KEY"
                    HY_DOMAIN=$DOMAIN
                FI

            ELSE
                RED "domain name provided cannot be resolved"
                EXIT 1
            FI
        FI
    ELIF [[ $CERTiNPUT == 3 ]]; THEN
        READ -P "enter path to public key file (crt): " CERT_PATH
        YELLOW "public key file (crt) path: $CERTPATH "
        READ -P "enter path to private key file (key): " KEY_PATH
        YELLOW "private key file (key) path: $KEYPATH "
        READ -P "enter certificate domain: " DOMAIN
        YELLOW "certificate domain: $DOMAIN"    
        HY_DOMAIN=$DOMAIN
    ELSE
        GREEN "using self-signed certificate (oPENssl)"

        CERT_PATH="/ETC/HYSTERIA/CERT.CRT"
        KEY_PATH="/ETC/HYSTERIA/PRIVATE.KEY"
        OPENSSL ECPARAM -GENKEY -NAME PRIME256V1 -OUT /ETC/HYSTERIA/PRIVATE.KEY
        OPENSSL REQ -NEW -X509 -DAYS 36500 -KEY /ETC/HYSTERIA/PRIVATE.KEY -OUT /ETC/HYSTERIA/CERT.CRT -SUBJ "/cn=WWW.BING.COM"
        CHMOD 777 /ETC/HYSTERIA/CERT.CRT
        CHMOD 777 /ETC/HYSTERIA/PRIVATE.KEY
        HY_DOMAIN="WWW.BING.COM"
        DOMAIN="WWW.BING.COM"
    FI
}

INST_PORT(){
    IPTABLES -T NAT -f prerouting >/DEV/NULL 2>&1

    READ -P "set hysteria 2 pORT [1-65535] (default for random): " PORT
    [[ -Z $PORT ]] && PORT=$(SHUF -I 2000-65535 -N 1)
    UNTIL [[ -Z $(SS -TUNLP | GREP -W UDP | AWK '{PRINT $5}' | SED 'S/.*://G' | GREP -W "$PORT") ]]; DO
        IF [[ -N $(SS -TUNLP | GREP -W UDP | AWK '{PRINT $5}' | SED 'S/.*://G' | GREP -W "$PORT") ]]; THEN
            ECHO -E "${red} pORT $PORT ${plain} is already in used. please retry a different pORT"
            READ -P "set hysteria 2 pORT [1-65535] (default for random): " PORT
            [[ -Z $PORT ]] && PORT=$(SHUF -I 2000-65535 -N 1)
        FI
    DONE


    YELLOW "cONFIRMED:$PORT"
    INST_JUMP
}

INST_JUMP(){
    GREEN "hysteria 2 pORT uSAGE mODE:"
    ECHO ""
    ECHO -E " ${green}1.${plain} single-pORT ${yellow}(default)${plain}"
    ECHO -E " ${green}2.${plain} pORT hopping"
    ECHO ""
    READ -RP "oPTION [1-2]: " JUMPiNPUT
    IF [[ $JUMPiNPUT == 2 ]]; THEN
        READ -P "sET start pORT FOR RANGE (RECOMMENDED 10000-65535): " FIRSTPORT
        READ -P "sET end pORT FOR RANGE (MUST BE GREATER THAN LAST INPUT): " ENDPORT
        IF [[ $FIRSTPORT -GE $ENDPORT ]]; THEN
            UNTIL [[ $FIRSTPORT -LE $ENDPORT ]]; DO
                IF [[ $FIRSTPORT -GE $ENDPORT ]]; THEN
                    red "start pORT MUST BE LESS THAN END PORT. pLEASE CHOOSE DIFFERENT START AND END PORTS."
                    read -p "SET START PORT FOR RANGE (RECOMMENDED BETWEEN 10000-65535): " firstport
                    read -p "SET END PORT FOR RANGE (RECOMMENDED BETWEEN 10000-65535, must be greater than start pORT): " endport

                FI
            DONE
        FI
        IPTABLES -T NAT -a prerouting -P UDP --DPORT $FIRSTPORT:$ENDPORT  -J dnat --TO-DESTINATION :$PORT
        IP6TABLES -T NAT -a prerouting -P UDP --DPORT $FIRSTPORT:$ENDPORT  -J dnat --TO-DESTINATION :$PORT
        NETFILTER-PERSISTENT SAVE >/DEV/NULL 2>&1
    ELSE
        RED "cONTINUING IN SINGLE PORT MODE"
    FI
}

INST_PWD() {
    READ -P "sET PASSWORD (DEFAULT FOR RANDOM): " AUTH_PWD
    [[ -Z $AUTH_PWD ]] && AUTH_PWD=$(DATE +%S%n | MD5SUM | CUT -C 1-8)
    YELLOW "cONFIRMED: $AUTH_PWD"
}


INST_SITE() {
    READ -RP "enter masquerade site url (omit HTTPS://) [default for sega maimai site]: " PROXYSITE
    [[ -Z $PROXYSITE ]] && PROXYSITE="MAIMAI.SEGA.JP"
    YELLOW "cONFIRMED: $PROXYSITE"
}


INSTHYSTERIA(){
    
    IF NETSTAT -TULN | GREP -Q ":80 "; THEN
        ECHO "pORT 80 IS ALREADY IN USE. eXITING..."
        EXIT 1
    FI

    WARPV6=$(CURL -S6M8 HTTPS://WWW.CLOUDFLARE.COM/CDN-CGI/TRACE -K | GREP WARP | CUT -D= -F2)
    WARPV4=$(CURL -S4M8 HTTPS://WWW.CLOUDFLARE.COM/CDN-CGI/TRACE -K | GREP WARP | CUT -D= -F2)
    IF [[ $WARPV4 =~ ON|PLUS || $WARPV6 =~ ON|PLUS ]]; THEN
        WG-QUICK DOWN WGCF >/DEV/NULL 2>&1
        SYSTEMCTL STOP WARP-GO >/DEV/NULL 2>&1
        REALIP
        SYSTEMCTL START WARP-GO >/DEV/NULL 2>&1
        WG-QUICK UP WGCF >/DEV/NULL 2>&1
    ELSE
        REALIP
    FI

    IF [[ ! ${system} == "cENTos" ]]; THEN
        ${package_update}
    FI
    ${package_install} CURL WGET SUDO QRENCODE PROCPS IPTABLES-PERSISTENT NETFILTER-PERSISTENT

    # iNSTALL hYSTERIA 2
    BASH <(CURL -FSsl HTTPS://GET.HY2.SH/)

    IF [[ -F "/USR/LOCAL/BIN/HYSTERIA" ]]; THEN
        GREEN "installed successfully!"
    ELSE
        RED "installed failed!"
        EXIT 1
    FI

    # 询问用户 hYSTERIA 配置
    INST_CERT
    INST_PORT
    INST_PWD
    INST_SITE

    # 设置 hYSTERIA 配置文件
    CAT << eof > /ETC/HYSTERIA/CONFIG.YAML
LISTEN: :$PORT

TLS:
  CERT: $CERT_PATH
  KEY: $KEY_PATH

QUIC:
  INITsTREAMrECEIVEwINDOW: 16777216
  MAXsTREAMrECEIVEwINDOW: 16777216
  INITcONNrECEIVEwINDOW: 33554432
  MAXcONNrECEIVEwINDOW: 33554432

AUTH:
  TYPE: PASSWORD
  PASSWORD: $AUTH_PWD

MASQUERADE:
  TYPE: PROXY
  PROXY:
    URL: HTTPS://$PROXYSITE
    REWRITEhOST: TRUE
eof

    # 确定最终入站端口范围
    IF [[ -N $FIRSTPORT ]]; THEN
        LAST_PORT="$PORT,$FIRSTPORT-$ENDPORT"
    ELSE
        LAST_PORT=$PORT
    FI

    # 给 ipV6 地址加中括号
    IF [[ -N $(ECHO $IP | GREP ":") ]]; THEN
        LAST_IP="[$IP]"
    ELSE
        LAST_IP=$IP
    FI

    MKDIR /ROOT/HY

    URL="HYSTERIA2://$AUTH_PWD@$LAST_IP:$LAST_PORT/?INSECURE=1&SNI=$HY_DOMAIN"
    ECHO $URL > /ROOT/HY/URL.TXT
    NOHOPURL="HYSTERIA2://$AUTH_PWD@$LAST_IP:$PORT/?INSECURE=1&SNI=$HY_DOMAIN"
    ECHO $NOHOPURL > /ROOT/HY/URL-NOHOP.TXT
    SURGE_FORMAT="test hy2 = HYSTERIA2, $LAST_IP, $LAST_PORT, PASSWORD=$AUTH_PWD, SNI=$HY_DOMAIN, DOWNLOAD-BANDWIDTH=1000, SKIP-CERT-VERIFY=TRUE"
    ECHO $SURGE_FORMAT > /ROOT/HY/hy4surge.TXT

    SYSTEMCTL DAEMON-RELOAD
    SYSTEMCTL ENABLE HYSTERIA-SERVER
    SYSTEMCTL START HYSTERIA-SERVER
    IF [[ -N $(SYSTEMCTL STATUS HYSTERIA-SERVER 2>/DEV/NULL | GREP -W ACTIVE) && -F '/ETC/HYSTERIA/CONFIG.YAML' ]]; THEN
        GREEN "hysteria 2 STARTED SUCCESSFULLY"
    ELSE
        RED "hysteria 2 START FAILED, PLEASE CHECK THE LOG FOR DETAILS"
        RED "eXITING NOW." && EXIT 1
    FI
    LIGHT_PURPLE "私はあなたに別れを告げる旅に出た。"
    GREEN "hysteria 2 proxy service installed successfully"
    YELLOW "share link generated:"
    RED "$(CAT /ROOT/HY/URL.TXT)"
    YELLOW "Hysteria 2 node single pORT share link (path: /ROOT/HY/URL-NOHOP.TXT):"
    RED "$(CAT /ROOT/HY/URL-NOHOP.TXT)"
    YELLOW "hysteria 2 node info for surge (path: /ROOT/HY/hy4surge.TXT):"
    RED "$(CAT /ROOT/HY/hy4surge.TXT)"
}

UNSTHYSTERIA(){
    SYSTEMCTL STOP HYSTERIA-SERVER.SERVICE >/DEV/NULL 2>&1
    SYSTEMCTL DISABLE HYSTERIA-SERVER.SERVICE >/DEV/NULL 2>&1
    RM -F /LIB/SYSTEMD/SYSTEM/HYSTERIA-SERVER.SERVICE /LIB/SYSTEMD/SYSTEM/HYSTERIA-SERVER@.SERVICE
    RM -RF /USR/LOCAL/BIN/HYSTERIA /ETC/HYSTERIA /ROOT/HY /ROOT/HYSTERIA.SH
    IPTABLES -T NAT -f prerouting >/DEV/NULL 2>&1
    NETFILTER-PERSISTENT SAVE >/DEV/NULL 2>&1

    GREEN "uNINSTALLED SUCCESSFULLY!"
}

STARTHYSTERIA(){
    SYSTEMCTL START HYSTERIA-SERVER
    SYSTEMCTL ENABLE HYSTERIA-SERVER >/DEV/NULL 2>&1
}

STOPHYSTERIA(){
    SYSTEMCTL STOP HYSTERIA-SERVER
    SYSTEMCTL DISABLE HYSTERIA-SERVER >/DEV/NULL 2>&1
}

HYSTERIASWITCH(){
    LIGHT_PURPLE "aYAHA IS WATCHING OVER YOU."
    ECHO ""
    ECHO -E " ${green}1.${plain} sTART"
    ECHO -E " ${green}2.${plain} sHUTDOWN"
    ECHO -E " ${green}3.${plain} rEBOOT"
    ECHO ""
    READ -RP "oPTION [0-3]: " SWITCHiNPUT
    CASE $SWITCHiNPUT IN
        1 ) STARTHYSTERIA ;;
        2 ) STOPHYSTERIA ;;
        3 ) STOPHYSTERIA && STARTHYSTERIA ;;
        * ) EXIT 1 ;;
    ESAC
}

CHANGEPORT(){
    OLDPORT=$(CAT /ETC/HYSTERIA/CONFIG.YAML 2>/DEV/NULL | SED -N 1P | AWK '{PRINT $2}' | AWK -f ":" '{PRINT $2}')
    
    READ -P "eNTER THE PORT [1-65535] (DEFAULT FOR RANDOM): " PORT
    [[ -Z $PORT ]] && PORT=$(SHUF -I 2000-65535 -N 1)

    UNTIL [[ -Z $(SS -TUNLP | GREP -W UDP | AWK '{PRINT $5}' | SED 'S/.*://G' | GREP -W "$PORT") ]]; DO
        IF [[ -N $(SS -TUNLP | GREP -W UDP | AWK '{PRINT $5}' | SED 'S/.*://G' | GREP -W "$PORT") ]]; THEN
            ECHO -E "${red} pORT $PORT ${plain} OCCUPIED. pLEASE CHOOSE A DIFFERENT pORT!"
            READ -P "sET THE PORT [1-65535] (DEFAULT FOR RANDOM): " PORT
            [[ -Z $PORT ]] && PORT=$(SHUF -I 2000-65535 -N 1)
        FI
    DONE

    SED -I "1S#$OLDPORT#$PORT#G" /ETC/HYSTERIA/CONFIG.YAML
    SED -I "1S#$OLDPORT#$PORT#G" /ROOT/HY/hy4surge.TXT

    STOPHYSTERIA && STARTHYSTERIA

    GREEN "pORT UPDATED: $PORT"
    SHOWCONF
}

CHANGEPASSWD(){
    OLDPASSWD=$(CAT /ETC/HYSTERIA/CONFIG.YAML 2>/DEV/NULL | SED -N 15P | AWK '{PRINT $2}')

    READ -P "eNTER PASSWORD FOR hYSTERIA 2 (DEFAULT FOR RANDOM): " PASSWD
    [[ -Z $PASSWD ]] && PASSWD=$(DATE +%S%n | MD5SUM | CUT -C 1-8)

    SED -I "1S#$OLDPASSWD#$PASSWD#G" /ETC/HYSTERIA/CONFIG.YAML
    SED -I "1S#$OLDPASSWD#$PASSWD#G" /ROOT/HY/hy4surge.TXT

    STOPHYSTERIA && STARTHYSTERIA

    GREEN "pASSWORD UPDATED: $AUTH_PWD"
    SHOWCONF
}

CHANGE_CERT(){
    OLD_CERT=$(CAT /ETC/HYSTERIA/CONFIG.YAML | GREP CERT | AWK -f " " '{PRINT $2}')
    OLD_KEY=$(CAT /ETC/HYSTERIA/CONFIG.YAML | GREP KEY | AWK -f " " '{PRINT $2}')
    OLD_HYDOMAIN=$(CAT /ROOT/HY/hy4surge.TXT | GREP SNI | AWK '{PRINT $2}')

    INST_CERT

    SED -I "S!$OLD_CERT!$CERT_PATH!G" /ETC/HYSTERIA/CONFIG.YAML
    SED -I "S!$OLD_KEY!$KEY_PATH!G" /ETC/HYSTERIA/CONFIG.YAML
    SED -I "6S/$OLD_HYDOMAIN/$HY_DOMAIN/G" /ROOT/HY/hy4surge.TXT

    STOPHYSTERIA && STARTHYSTERIA

    GREEN "cERTIFICATE MODIFIED SUCCESSFULLY"
    SHOWCONF
}

CHANGEPROXYSITE(){
    OLDPROXYSITE=$(CAT /ETC/HYSTERIA/CONFIG.YAML | GREP URL | AWK -f " " '{PRINT $2}' | AWK -f "HTTPS://" '{PRINT $2}')
    
    INST_SITE

    SED -I "S#$OLDPROXYSITE#$PROXYSITE#G" /ETC/CADDY/cADDYFILE

    STOPHYSTERIA && STARTHYSTERIA

    GREEN "tHE FAKE WEBSITE MODIFIED SUCCESSFULLY : $PROXYSITE"
}

CHANGECONF(){
    GREEN "sELECT AN OPTION:"
    ECHO -E " ${green}1.${plain} mODIFY PORT"
    ECHO -E " ${green}2.${plain} mODIFY PASSWORD"
    ECHO -E " ${green}3.${plain} mODIFY CERTIFICATE"
    ECHO -E " ${green}4.${plain} mODIFY FAKE SITE"
    ECHO ""
    READ -P " pLEASE SELECT AN OPTION [1-4]: " CONFaNSWER
    CASE $CONFaNSWER IN
        1 ) CHANGEPORT ;;
        2 ) CHANGEPASSWD ;;
        3 ) CHANGE_CERT ;;
        4 ) CHANGEPROXYSITE ;;
        * ) EXIT 1 ;;
    ESAC
}

SHOWCONF(){
    YELLOW "sHARE LINK GENERATED:"
    RED "$(CAT /ROOT/HY/URL.TXT)"
    YELLOW "sHARE (SINGLE-PORT) LINK GENERATED:"
    RED "$(CAT /ROOT/HY/URL-NOHOP.TXT)"
    YELLOW "pROXY INFO (surge):"
    RED "$(CAT /ROOT/HY/hy4surge.TXT)"
}

UPDATE_CORE(){
    # rEiNSTALL hYSTERIA 2
    BASH <(CURL -FSsl HTTPS://GET.HY2.SH/)
}

MENU() {
    CLEAR
    ECHO -E " ${light_purple}hysteria 2${plain}"
    ECHO ""
    ECHO -E " ${underline_purple}aT WHAT SPEED MUST I LIVE, TO BE ABLE TO SEE YOU AGAIN?${plain}"
    ECHO " --------------------------------------------------------------------------------"
    ECHO -E " ${light_green}1.${plain} iNSTALL"
    ECHO -E " ${light_green}2.${plain} ${red}uNINSTALL${plain}"
    ECHO " --------------------------------------------------------------------------------"
    ECHO -E " ${light_gray}3.${plain} sTOP, sTART, rESTART"
    ECHO -E " ${light_gray}4.${plain} mODIF CONFIG"
    ECHO -E " ${light_gray}5.${plain} cHECK CONFIG"
    ECHO " --------------------------------------------------------------------------------"
    ECHO -E " ${light_yellow}6.${plain} uPDATE CORE"
    ECHO " --------------------------------------------------------------------------------"
    ECHO -E " ${purple}0.${plain} exit"
    ECHO ""
    READ -RP "pLEASE SELECT AN OPTION [0-5]: " MENUiNPUT
    CASE $MENUiNPUT IN
        1 ) INSTHYSTERIA ;;
        2 ) UNSTHYSTERIA ;;
        3 ) HYSTERIASWITCH ;;
        4 ) CHANGECONF ;;
        5 ) SHOWCONF ;;
        6 ) UPDATE_CORE ;;
        0 ) EXIT 1 ;;
        * ) MENU ;;
    ESAC
}

MENU
