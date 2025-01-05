#!/bin/bash
##############################################################################
# Mega-Script for:
#   - Pi-hole (Optionally configures static IP via dhcpcd if chosen)
#   - Tailscale
#   - Unbound (dynamic CPU threads, with or without Cloudflared)
#   - Cloudflared (DoH)
#   - HTTPS (Self-Signed Cert for Lighttpd)
#
# Compatible with:
#   - Raspberry Pi OS (Raspbian)
#   - Armbian
#   - Ubuntu
#   - Debian
#   - Fedora
#   - CentOS (or CentOS Stream)
#
# If Unbound is selected but Cloudflared is NOT, uses a recursive config snippet.
# If both Unbound & Cloudflared are selected, forwards to 127.0.0.1@5053.
#
# If user selects only Pi-hole (no Unbound or Cloudflared), Pi-hole's DNS => 1.1.1.1
# If user selects Pi-hole + Cloudflared (no Unbound), Pi-hole's DNS => 127.0.0.1#5053
#
# USE AT YOUR OWN RISK.
##############################################################################

##############################################################################
# 0) Must be root
##############################################################################
if [ "$(id -u)" -ne 0 ]; then
    echo "[ERROR] Script must be run as root (sudo)."
    exit 1
fi

##############################################################################
# 1) Basic Logging
##############################################################################
log_message() {
    local TYPE="$1"
    local MESSAGE="$2"
    echo "[$TYPE] $MESSAGE"
}

##############################################################################
# 2) Minimal OS detection just to install 'dialog'
##############################################################################
PKG_MANAGER=""
OS_TYPE=""

if command -v apt-get &>/dev/null; then
    PKG_MANAGER="apt-get"
    OS_TYPE="debian"
elif command -v apt &>/dev/null; then
    PKG_MANAGER="apt"
    OS_TYPE="debian"
elif command -v dnf &>/dev/null; then
    PKG_MANAGER="dnf"
    OS_TYPE="fedora"
elif command -v yum &>/dev/null; then
    PKG_MANAGER="yum"
    OS_TYPE="centos"
else
    log_message "ERROR" "No supported package manager found (need apt-get, apt, dnf, yum)."
    exit 1
fi

log_message "INFO" "Detected OS type: $OS_TYPE"
log_message "INFO" "Detected package manager for installing 'dialog': $PKG_MANAGER"

##############################################################################
# 3) Install 'dialog' if missing
##############################################################################
install_dialog() {
    local PACKAGE="dialog"
    case "$PKG_MANAGER" in
        apt-get|apt)
            apt-get update -y || apt update -y
            apt-get install -y "$PACKAGE" || apt install -y "$PACKAGE"
            ;;
        dnf)
            dnf install -y "$PACKAGE"
            ;;
        yum)
            yum install -y "$PACKAGE"
            ;;
        *)
            log_message "ERROR" "Cannot install '$PACKAGE' with unknown manager: $PKG_MANAGER."
            exit 1
            ;;
    esac
}

if ! command -v dialog &>/dev/null; then
    log_message "INFO" "Installing 'dialog' for interactive menus..."
    install_dialog
fi

##############################################################################
# 4) Show the Selection Menu
##############################################################################
SELECTION=$(
    dialog --clear \
        --backtitle "Universal Setup" \
        --title "Components" \
        --checklist "Select items to install/configure (all ON by default):" \
        20 78 5 \
        "1" "Pi-hole (also sets static IP via dhcpcd)" ON \
        "2" "Tailscale" ON \
        "3" "Unbound (Dynamic threads)" ON \
        "4" "Cloudflared (DoH)" ON \
        "5" "HTTPS (Self-Signed Lighttpd)" ON \
        3>&1 1>&2 2>&3
)

if [ $? -ne 0 ]; then
    log_message "INFO" "Setup canceled by user or ESC pressed."
    exit 0
fi

log_message "INFO" "User selected: $SELECTION"

##############################################################################
# 5) Determine if Unbound or Cloudflared are chosen
##############################################################################
UNBOUND_SELECTED="false"
CLOUDFLARED_SELECTED="false"

if echo "$SELECTION" | grep -q "\"3\""; then
    UNBOUND_SELECTED="true"
fi
if echo "$SELECTION" | grep -q "\"4\""; then
    CLOUDFLARED_SELECTED="true"
fi

##############################################################################
# 6) Full OS detection for the rest and system update
##############################################################################
PKG_MANAGER_FULL=""
OS_TYPE_FULL=""

if command -v apt-get &>/dev/null; then
    PKG_MANAGER_FULL="apt-get"
    OS_TYPE_FULL="debian"
elif command -v apt &>/dev/null; then
    PKG_MANAGER_FULL="apt"
    OS_TYPE_FULL="debian"
elif command -v dnf &>/dev/null; then
    PKG_MANAGER_FULL="dnf"
    OS_TYPE_FULL="fedora"
elif command -v yum &>/dev/null; then
    PKG_MANAGER_FULL="yum"
    OS_TYPE_FULL="centos"
else
    log_message "ERROR" "No supported package manager for full operations."
    exit 1
fi

log_message "INFO" "Detected manager for main ops: $PKG_MANAGER_FULL ($OS_TYPE_FULL)"

case "$PKG_MANAGER_FULL" in
    apt-get|apt)
        log_message "INFO" "Updating system (Debian/Ubuntu/Armbian/RPi OS)..."
        apt update && apt upgrade -y
        ;;
    dnf)
        log_message "INFO" "Updating system (Fedora)..."
        dnf upgrade -y
        ;;
    yum)
        log_message "INFO" "Updating system (CentOS)..."
        yum update -y
        ;;
    *)
        log_message "WARNING" "Unknown manager for updates. Skipping system update."
        ;;
esac

##############################################################################
# 7) Helper: universal_install_package / restart_service
##############################################################################
universal_install_package() {
    local PACKAGE="$1"
    case "$PKG_MANAGER_FULL" in
        apt-get|apt)
            apt-get update -y || apt update -y
            apt-get install -y "$PACKAGE" || apt install -y "$PACKAGE"
            ;;
        dnf)
            dnf install -y "$PACKAGE"
            ;;
        yum)
            yum install -y "$PACKAGE"
            ;;
        *)
            log_message "ERROR" "Cannot install $PACKAGE with $PKG_MANAGER_FULL."
            exit 1
            ;;
    esac
}

restart_service() {
    local SERVICE="$1"
    if command -v systemctl &>/dev/null; then
        systemctl restart "$SERVICE"
    elif [ -x "/etc/init.d/$SERVICE" ]; then
        /etc/init.d/$SERVICE restart
    else
        log_message "WARNING" "Cannot restart $SERVICE automatically."
    fi
}


setup_adlists() {
    log_message "INFO" "Adding custom adlists to /etc/pihole/gravity.db..."

    # Vetor de adlists "URL|Comentario"
    local ADLISTS=(
        "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts|DefaultAllow"
        "https://raw.githubusercontent.com/PolishFiltersTeam/KADhosts/master/KADhosts.txt|DefaultAllow"
        "https://adaway.org/hosts.txt|DefaultAllow"
        "https://v.firebog.net/hosts/AdguardDNS.txt|DefaultAllow"
        "https://v.firebog.net/hosts/Easyprivacy.txt|DefaultAllow"
        "https://v.firebog.net/hosts/Prigent-Ads.txt|DefaultAllow"
        "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareHosts.txt|DefaultAllow"
        "https://zerodot1.gitlab.io/CoinBlockerLists/hosts_browser|DefaultAllow"
        "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/domains/pro.plus.txt|DefaultAllow"
    )

    # Verifica se o /etc/pihole/gravity.db existe
    if [ ! -f /etc/pihole/gravity.db ]; then
        log_message "ERROR" "File /etc/pihole/gravity.db not found. Pi-hole likely not installed yet."
        return 1
    fi

    # Inserir cada URL no adlist
    for ENTRY in "${ADLISTS[@]}"; do
        local URL=$(echo "$ENTRY" | cut -d'|' -f1)
        local COMMENT=$(echo "$ENTRY" | cut -d'|' -f2)

        log_message "INFO" "Inserting $URL (comment: $COMMENT)"
        sqlite3 /etc/pihole/gravity.db <<SQL
INSERT OR IGNORE INTO adlist (address, enabled, comment)
VALUES ("$URL", 1, "$COMMENT");
SQL
    done

    # Reinicia o DNS do Pi-hole para recarregar
    log_message "INFO" "Restarting Pi-hole DNS after adlists insertion..."
    pihole restartdns

    log_message "INFO" "Adlists insertion completed!"
}



##############################################################################
# 8) Setup Functions
##############################################################################
setup_pihole() {
    log_message "INFO" "Setting up Pi-hole..."

    # (1) Install & enable dhcpcd
    universal_install_package "dhcpcd"

    if command -v systemctl &>/dev/null; then
        systemctl enable dhcpcd
        systemctl start dhcpcd
    elif [ -x "/etc/init.d/dhcpcd" ]; then
        /etc/init.d/dhcpcd start
    fi

    # (2) Overwrite /etc/dhcpcd.conf
    PI_IP=$(hostname -I | awk '{print $1}')
    GATEWAY_IP=$(ip route | grep default | awk '{print $3}')
    [ -z "$PI_IP" ] && PI_IP="192.168.0.17"
    [ -z "$GATEWAY_IP" ] && GATEWAY_IP="192.168.0.1"

cat <<EOF >/etc/dhcpcd.conf
# Universal dhcpcd configuration for static IP on eth0
noipv6rs
noipv6
ipv4only

interface eth0
    static ip_address=$PI_IP/24
    static routers=$GATEWAY_IP
    static domain_name_servers=$GATEWAY_IP 1.1.1.1

duid
persistent
vendorclassid
option domain_name_servers, domain_name, domain_search
option classless_static_routes
option interface_mtu
option host_name
option rapid_commit
require dhcp_server_identifier
slaac private
EOF

    # Reinicia dhcpcd
    if command -v systemctl &>/dev/null; then
        systemctl restart dhcpcd
        log_message "INFO" "Restarted dhcpcd with systemctl."
    else
        [ -x "/etc/init.d/dhcpcd" ] && /etc/init.d/dhcpcd restart
    fi

    # (3) Instalar Pi-hole
    curl -sSL https://install.pi-hole.net | bash

    # (4) Se Pi-hole estiver instalado, ajusta DNS + flags extras
    if command -v pihole &>/dev/null; then
        log_message "INFO" "Pi-hole installed successfully."

        # Se Unbound não selecionado, então checar Cloudflared
        if [ "$UNBOUND_SELECTED" = "false" ]; then
            if [ "$CLOUDFLARED_SELECTED" = "true" ]; then
                # Se Cloudflared mas não Unbound => 127.0.0.1#5053
                log_message "INFO" "Setting Pi-hole upstream DNS to 127.0.0.1#5053"
                sed -i '/^PIHOLE_DNS_2=/d' /etc/pihole/setupVars.conf 2>/dev/null
                sed -i '/^PIHOLE_DNS_1=/d' /etc/pihole/setupVars.conf 2>/dev/null
                echo "PIHOLE_DNS_1=127.0.0.1#5053" >> /etc/pihole/setupVars.conf

                if [ -f "/etc/dnsmasq.d/01-pihole.conf" ]; then
                    sed -i '/^server=/d' /etc/dnsmasq.d/01-pihole.conf
                    echo "server=127.0.0.1#5053" >> /etc/dnsmasq.d/01-pihole.conf
                fi
            else
                # Se nem Unbound nem Cloudflared => DNS=1.1.1.1
                log_message "INFO" "Setting Pi-hole upstream DNS to 1.1.1.1"
                sed -i '/^PIHOLE_DNS_2=/d' /etc/pihole/setupVars.conf 2>/dev/null
                sed -i '/^PIHOLE_DNS_1=/d' /etc/pihole/setupVars.conf 2>/dev/null
                echo "PIHOLE_DNS_1=1.1.1.1" >> /etc/pihole/setupVars.conf

                if [ -f "/etc/dnsmasq.d/01-pihole.conf" ]; then
                    sed -i '/^server=/d' /etc/dnsmasq.d/01-pihole.conf
                    echo "server=1.1.1.1" >> /etc/dnsmasq.d/01-pihole.conf
                fi
            fi
            restart_service "pihole-FTL"
        fi

        # =====================================================================
        # => Sobrescrever /etc/pihole/pihole-FTL.conf com as flags extras:
        # =====================================================================
cat <<EOPFTLCFG >/etc/pihole/pihole-FTL.conf
SOCKET_LISTENING=all
DNS_FQDN_REQUIRED=true
DNS_BOGUS_PRIV=false
DNSSEC=false
RATE_LIMIT=5000/60
EOPFTLCFG

        # =====================================================================
        # => Ajustar /etc/pihole/setupVars.conf com Conditional Forwarding etc.
        # =====================================================================
        # Remover linhas existentes antes de adicionar:
        sed -i '/^REV_SERVER/d' /etc/pihole/setupVars.conf 2>/dev/null
        sed -i '/^REV_SERVER_/d' /etc/pihole/setupVars.conf 2>/dev/null
        sed -i '/^SHOW_DNSSEC=/d' /etc/pihole/setupVars.conf 2>/dev/null

        echo "REV_SERVER=true" >> /etc/pihole/setupVars.conf
        echo "REV_SERVER_CIDR=192.168.0.0/24" >> /etc/pihole/setupVars.conf
        echo "REV_SERVER_TARGET=$GATEWAY_IP" >> /etc/pihole/setupVars.conf
        echo "REV_SERVER_DOMAIN=local.lan" >> /etc/pihole/setupVars.conf
        echo "SHOW_DNSSEC=false" >> /etc/pihole/setupVars.conf

        # Reinicia o pihole-FTL para aplicar as novas configs
        restart_service "pihole-FTL"

        # Redefine a senha do Pi-hole
        log_message "INFO" "Setting a new Pi-hole admin password..."
        pihole -a -p
    else
        log_message "ERROR" "Pi-hole command not found; installation might have failed."
    fi
}

setup_tailscale() {
    log_message "INFO" "Installing Tailscale..."

    # Ajuste no /etc/rc.local
    if [ ! -f /etc/rc.local ]; then
cat <<'EOF' > /etc/rc.local
#!/bin/bash
# rc.local for persistent custom commands

exit 0
EOF
        chmod +x /etc/rc.local
    fi
    sed -i '/^exit 0$/d' /etc/rc.local

cat <<'EOF' >> /etc/rc.local

# Enable UDP GRO forwarding
ethtool -K eth0 rx-udp-gro-forwarding on rx-gro-list off

    if [ "$OS_TYPE_FULL" = "fedora" ] || [ "$OS_TYPE_FULL" = "centos" ] || [ "$OS_TYPE_FULL" = "debian" ]; then
        # Instala via script universal
        curl -fsSL https://tailscale.com/install.sh | bash
        if ! command -v tailscale &>/dev/null; then
            log_message "ERROR" "Tailscale installation failed."
            return
        fi
        systemctl enable --now tailscaled 2>/dev/null || true
    else
        # Se for outro Debian-like (Armbian, Raspberry Pi OS), assume apt-get
        if [ "$PKG_MANAGER_FULL" = "apt-get" ] || [ "$PKG_MANAGER_FULL" = "apt" ]; then
            curl -fsSL https://tailscale.com/install.sh | bash
            if ! command -v tailscale &>/dev/null; then
                log_message "ERROR" "Tailscale installation failed."
                return
            fi
            systemctl enable --now tailscaled 2>/dev/null || true
        else
            log_message "WARNING" "Not a recognized distro for Tailscale. Attempting universal script anyway."
            curl -fsSL https://tailscale.com/install.sh | bash || true
        fi
    fi

    tailscale up --accept-routes --accept-dns=false --advertise-exit-node \
        --advertise-routes=192.168.0.0/24,192.168.1.0/24

exit 0
EOF
    log_message "INFO" "Tailscale setup complete!"
}

setup_unbound() {
    log_message "INFO" "Installing Unbound..."
    universal_install_package "unbound"

    CPU_THREADS=$(nproc --all 2>/dev/null)
    [ -z "$CPU_THREADS" ] && CPU_THREADS=1

    local CONF_DIR="/etc/unbound/unbound.conf.d"
    local CONF_FILE="$CONF_DIR/pi-hole.conf"
    mkdir -p "$CONF_DIR"

    if [ -f "$CONF_FILE" ]; then
        cp "$CONF_FILE" "${CONF_FILE}.bkp.$(date +%s)"
    fi

    if [ "$CLOUDFLARED_SELECTED" = "true" ]; then
cat <<EOF > "$CONF_FILE"
server:
    verbosity: 0
    interface: 127.0.0.1
    port: 5335
    do-ip4: yes
    do-udp: yes
    do-tcp: yes
    do-ip6: no
    cache-max-ttl: 259200
    cache-min-ttl: 14400
    rrset-cache-size: 400m
    msg-cache-size: 200m
    outgoing-range: 4096

    # CPU threads
    num-threads: $CPU_THREADS
    msg-cache-slabs: $CPU_THREADS
    rrset-cache-slabs: $CPU_THREADS
    infra-cache-slabs: $CPU_THREADS
    key-cache-slabs: $CPU_THREADS

    prefetch: yes
    prefetch-key: yes
    serve-expired: yes
    serve-expired-reply-ttl: 3600

    so-rcvbuf: 256m
    so-sndbuf: 128m

    private-address: 192.168.0.0/16
    private-address: 169.254.0.0/16
    private-address: 172.16.0.0/12
    private-address: 10.0.0.0/8
    private-address: 100.64.0.0/10
    private-address: fd00::/8
    private-address: fe80::/10

    log-queries: no
    log-replies: no
    do-not-query-localhost: no
    val-permissive-mode: yes
    harden-algo-downgrade: no
    harden-dnssec-stripped: no
    harden-referral-path: yes
    so-reuseport: yes

    forward-zone:
        name: "."
        forward-addr: 127.0.0.1@5053
        forward-first: no
EOF
    else
cat <<EOF > "$CONF_FILE"
server:
    verbosity: 0
    interface: 127.0.0.1
    port: 5335
    do-ip4: yes
    do-udp: yes
    do-tcp: yes
    do-ip6: no
    cache-max-ttl: 259200
    cache-min-ttl: 14400
    rrset-cache-size: 400m
    msg-cache-size: 200m
    outgoing-range: 4096
    num-queries-per-thread: 4096
    prefetch: yes
    prefetch-key: yes
    serve-expired: yes
    serve-expired-reply-ttl: 3600

    # CPU threads
    num-threads: $CPU_THREADS
    msg-cache-slabs: $CPU_THREADS
    rrset-cache-slabs: $CPU_THREADS
    infra-cache-slabs: $CPU_THREADS
    key-cache-slabs: $CPU_THREADS

    so-rcvbuf: 256m
    so-sndbuf: 128m
    private-address: 192.168.0.0/16
    private-address: 169.254.0.0/16
    private-address: 172.16.0.0/12
    private-address: 10.0.0.0/8
    private-address: 100.64.0.0/10
    private-address: fd00::/8
    private-address: fe80::/10
    log-queries: no
    log-replies: no
    logfile: "/var/log/unbound/unbound.log"
    do-not-query-localhost: no
    val-permissive-mode: yes
    harden-algo-downgrade: no
    harden-dnssec-stripped: no
    harden-referral-path: yes
    so-reuseport: yes
EOF
    fi

    # Ajusta DNS do Pi-hole => 127.0.0.1#5335
    if command -v pihole &>/dev/null; then
        sed -i '/^PIHOLE_DNS_2=/d' /etc/pihole/setupVars.conf 2>/dev/null
        sed -i '/^PIHOLE_DNS_1=/d' /etc/pihole/setupVars.conf 2>/dev/null
        echo "PIHOLE_DNS_1=127.0.0.1#5335" >> /etc/pihole/setupVars.conf

        if [ -f "/etc/dnsmasq.d/01-pihole.conf" ]; then
            sed -i '/^server=/d' /etc/dnsmasq.d/01-pihole.conf
            echo "server=127.0.0.1#5335" >> /etc/dnsmasq.d/01-pihole.conf
        fi
        restart_service "pihole-FTL"
    fi

    restart_service "unbound"
    log_message "INFO" "Unbound setup complete!"
}

setup_cloudflared() {
    log_message "INFO" "Installing Cloudflared..."
    CLOUDFLARED_SELECTED="true"

    universal_install_package "wget"
    ARCH=$(uname -m | tr '[:upper:]' '[:lower:]')
    local CF_DEB=""
    local CF_RPM=""

    case "$ARCH" in
        x86_64|amd64)
            CF_DEB="cloudflared-linux-amd64.deb"
            CF_RPM="cloudflared-linux-x86_64.rpm"
            ;;
        arm64|aarch64)
            CF_DEB="cloudflared-linux-arm64.deb"
            CF_RPM="cloudflared-linux-arm64.rpm"
            ;;
        armv7l|armv6l|armhf)
            CF_DEB="cloudflared-linux-arm.deb"
            CF_RPM="cloudflared-linux-arm.rpm"
            ;;
        i386|i686)
            CF_DEB="cloudflared-linux-386.deb"
            CF_RPM="cloudflared-linux-386.rpm"
            ;;
        *)
            CF_DEB="cloudflared-linux-amd64.deb"
            CF_RPM="cloudflared-linux-x86_64.rpm"
            log_message "WARNING" "Unknown arch. Using x86_64 fallback."
            ;;
    esac

    local BASE_URL="https://github.com/cloudflare/cloudflared/releases/latest/download"
    local TMP_FILE=""

    if [ "$OS_TYPE_FULL" = "debian" ]; then
        TMP_FILE="/tmp/$CF_DEB"
        wget -O "$TMP_FILE" "$BASE_URL/$CF_DEB"
        apt-get install -y "$TMP_FILE"
    elif [ "$OS_TYPE_FULL" = "fedora" ]; then
        TMP_FILE="/tmp/$CF_RPM"
        wget -O "$TMP_FILE" "$BASE_URL/$CF_RPM"
        dnf install -y "$TMP_FILE"
    elif [ "$OS_TYPE_FULL" = "centos" ]; then
        TMP_FILE="/tmp/$CF_RPM"
        wget -O "$TMP_FILE" "$BASE_URL/$CF_RPM"
        yum install -y "$TMP_FILE"
    else
        # Caso não seja Fedora/CentOS/Debian-like oficial, tentamos script manual
        wget -O /tmp/cloudflared.tgz "$BASE_URL/cloudflared-linux-amd64.tgz"
        tar -xvzf /tmp/cloudflared.tgz -C /usr/local/bin/ cloudflared
        chmod +x /usr/local/bin/cloudflared
    fi

    # Verifica se binário existe
    if ! command -v cloudflared &>/dev/null; then
        log_message "ERROR" "cloudflared not found. Possibly failed."
        return
    fi

    # Cria user 'cloudflared' (compatível com Debian, Ubuntu, Fedora, CentOS)
    if ! id "cloudflared" &>/dev/null; then
        NOLOGIN_SHELL="/usr/sbin/nologin"
        [ ! -f "$NOLOGIN_SHELL" ] && NOLOGIN_SHELL="/sbin/nologin"
        useradd -r -M -s "$NOLOGIN_SHELL" cloudflared 2>/dev/null || true
    fi

    mkdir -p /etc/default
cat <<EOF > /etc/default/cloudflared
CLOUDFLARED_OPTS="--port 5053 --upstream https://1.1.1.1/dns-query --upstream https://1.0.0.1/dns-query --max-upstream-conns 0 --metrics 0.0.0.0:44237"
EOF

    chown cloudflared:cloudflared /etc/default/cloudflared || true
    chown cloudflared:cloudflared /usr/local/bin/cloudflared 2>/dev/null || true

    # Cria serviço systemd
    if command -v systemctl &>/dev/null; then
cat <<'EOF' > /etc/systemd/system/cloudflared.service
[Unit]
Description=cloudflared DNS over HTTPS proxy
After=syslog.target network-online.target

[Service]
Type=simple
User=cloudflared
EnvironmentFile=/etc/default/cloudflared
ExecStart=/usr/local/bin/cloudflared proxy-dns $CLOUDFLARED_OPTS
Restart=on-failure
RestartSec=10
KillMode=process

[Install]
WantedBy=multi-user.target
EOF

        systemctl enable cloudflared
        systemctl start cloudflared
        log_message "INFO" "Cloudflared service enabled and started via systemd."
    else
        log_message "WARNING" "Systemd not found. Manage Cloudflared manually."
    fi

    log_message "INFO" "Cloudflared setup complete!"
}

setup_https() {
    log_message "INFO" "Setting up HTTPS (self-signed) for Lighttpd..."
    universal_install_package "lighttpd"
    universal_install_package "openssl"
    universal_install_package "jq"

    # Tenta instalar o módulo SSL
    if [ "$OS_TYPE_FULL" = "debian" ]; then
        universal_install_package "lighttpd-mod-openssl"
    elif [ "$OS_TYPE_FULL" = "fedora" ]; then
        dnf install -y lighttpd-mod-openssl || true
    elif [ "$OS_TYPE_FULL" = "centos" ]; then
        yum install -y lighttpd-mod-openssl || true
    fi

    local HOSTNAME_DETECTED
    HOSTNAME_DETECTED=$(hostname)
    local ALL_IPS
    ALL_IPS=$(hostname -I 2>/dev/null)
    local TAILSCALE_DNS=""

    if command -v tailscale &>/dev/null; then
        TAILSCALE_DNS=$(tailscale status -json 2>/dev/null | jq -r '.Self.DNSName' | sed 's/\.$//')
    fi

    mkdir -p /etc/ssl/mycerts
    cd /etc/ssl/mycerts || exit 1

cat <<EOF > openssl.cnf
[ req ]
default_bits        = 2048
default_keyfile     = $HOSTNAME_DETECTED.key
distinguished_name  = req_distinguished_name
req_extensions      = v3_req
prompt = no

[ req_distinguished_name ]
CN = $HOSTNAME_DETECTED

[ v3_req ]
subjectAltName = @alt_names
basicConstraints = CA:TRUE
keyUsage = digitalSignature, keyEncipherment, keyCertSign
extendedKeyUsage = serverAuth, clientAuth

[ alt_names ]
DNS.1 = $HOSTNAME_DETECTED
EOF

    if [ -n "$TAILSCALE_DNS" ] && [ "$TAILSCALE_DNS" != "null" ]; then
        echo "DNS.2 = $TAILSCALE_DNS" >> openssl.cnf
    fi

    local IP_INDEX=1
    for IP in $ALL_IPS; do
        echo "IP.$IP_INDEX = $IP" >> openssl.cnf
        IP_INDEX=$((IP_INDEX + 1))
    done

    openssl genpkey -algorithm RSA -out "$HOSTNAME_DETECTED.key" -pkeyopt rsa_keygen_bits:2048
    openssl req -new -x509 -key "$HOSTNAME_DETECTED.key" -out "$HOSTNAME_DETECTED.crt" \
        -config ./openssl.cnf -extensions v3_req -days 3650 -nodes

    cat "$HOSTNAME_DETECTED.key" "$HOSTNAME_DETECTED.crt" > "$HOSTNAME_DETECTED.pem"
    chmod 640 "$HOSTNAME_DETECTED.key" "$HOSTNAME_DETECTED.crt" "$HOSTNAME_DETECTED.pem"
    log_message "INFO" "Self-signed cert at /etc/ssl/mycerts/$HOSTNAME_DETECTED.pem"

    local LIGHTTPD_CONF="/etc/lighttpd/lighttpd.conf"
    if [ ! -f "$LIGHTTPD_CONF" ]; then
cat <<EOF > "$LIGHTTPD_CONF"
server.modules = (
    "mod_access",
    "mod_openssl"
)

server.document-root = "/var/www/html"
server.bind = "0.0.0.0"
server.port = 80
EOF
    fi

    if ! grep -q '"mod_openssl"' "$LIGHTTPD_CONF"; then
        sed -i '/server.modules = (/a\    "mod_openssl",' "$LIGHTTPD_CONF"
    fi

    if ! grep -q 'ssl.engine = "enable"' "$LIGHTTPD_CONF"; then
cat <<EOF >> "$LIGHTTPD_CONF"

# SSL config
\$SERVER["socket"] == ":443" {
    ssl.engine = "enable"
    ssl.pemfile = "/etc/ssl/mycerts/$HOSTNAME_DETECTED.pem"
}

# Redirect /admin from http to https
\$SERVER["socket"] == ":80" {
    url.redirect = (
        "^/admin(.*)" => "https://$HOSTNAME_DETECTED/admin\$1"
    )
}
EOF
    fi

    restart_service "lighttpd"

    if [ -d "/var/www/html" ]; then
        cp "$HOSTNAME_DETECTED.crt" /var/www/html/
        chmod 644 "/var/www/html/$HOSTNAME_DETECTED.crt"
        local FIRST_IP
        FIRST_IP=$(echo "$ALL_IPS" | awk '{print $1}')
        log_message "INFO" "Download cert at: http://$FIRST_IP/$HOSTNAME_DETECTED.crt"
    fi

    log_message "INFO" "HTTPS (Lighttpd) setup complete!"
}

##############################################################################
# 9) Executar as seleções
##############################################################################
for OPT in $SELECTION; do
    case "$OPT" in
        "\"1\"") setup_pihole ;;
        "\"2\"") setup_tailscale ;;
        "\"3\"") setup_unbound ;;
        "\"4\"") setup_cloudflared ;;
        "\"5\"") setup_https ;;
        *)
            log_message "WARNING" "Unknown option: $OPT. Skipping..."
            ;;
    esac
done

log_message "INFO" "All selected components have been configured successfully!"
exit 0
