#!/bin/bash

# ----------------------------------------------------------
#   LNID - Local Network Identity Discovery
#
#   Script installazione LNID Resolver daemon
#
# Copyright (c) 2024 Antonio Franco
# auth. A.Franco - INFN Bary Italy
# date: 06/12/2024       ver.2.1
# ---------------------------------------------------------

SERVICE_NAME="lnid-resolver"
EXEC_PATH="/usr/local/bin/lnid-resolver"
SERVICE_FILE="/etc/systemd/system/$SERVICE_NAME.service"
CONFIG_FILE="/etc/lnid-resolver.conf"

function error_exit {
    echo "$1" 1>&2
    exit 1
}

# Controllo privilegi root
if [ "$EUID" -ne 0 ]; then
    error_exit "Errore: sono necessari privilegi root per l'installazione"
fi

# Verifica esistenza eseguibile
if [ ! -f "$EXEC_PATH" ]; then
    error_exit "Errore: $EXEC_PATH non trovato. Compilare prima il progetto."
fi

# Crea file di configurazione
echo "Creazione file di configurazione..."
cat > "$CONFIG_FILE" <<EOL
# LNID Resolver Configuration
# Subnet da scansionare (senza .0 finale)
SUBNET=192.168.1

# Intervallo scansione in secondi (minimo 60)
SCAN_INTERVAL=300

# Porta LNID
PORT=16969

# Timeout richieste UDP in millisecondi
TIMEOUT=100

# Delay tra scansioni in millisecondi
DELAY=50

# Modalità cifrata (0=no, 1=si)
ENCRYPTED=0

# Modalità verbose (0=no, 1=si)
VERBOSE=0
EOL

# Crea file di servizio systemd
echo "Creazione servizio systemd..."
cat > "$SERVICE_FILE" <<EOL
[Unit]
Description=LNID Resolver Daemon
Documentation=https://github.com/fapfap69/lnid
After=network.target
Wants=network.target

[Service]
Type=forking
ExecStart=$EXEC_PATH
ExecReload=/bin/kill -HUP \$MAINPID
KillMode=process
Restart=on-failure
RestartSec=30
User=root
Group=root

# Sicurezza
NoNewPrivileges=true
ReadWritePaths=/etc/hosts /tmp
ProtectHome=true

[Install]
WantedBy=multi-user.target
EOL

# Imposta permessi
chmod 644 "$SERVICE_FILE"
chmod 600 "$CONFIG_FILE"

# Ricarica systemd
echo "Ricaricamento systemd..."
systemctl daemon-reload

# Abilita servizio
echo "Abilitazione servizio..."
systemctl enable "$SERVICE_NAME"

echo ""
echo "=== LNID Resolver installato con successo ==="
echo ""
echo "Configurazione:"
echo "  File config: $CONFIG_FILE"
echo "  Servizio: $SERVICE_NAME"
echo ""
echo "Comandi utili:"
echo "  Avvia:    sudo systemctl start $SERVICE_NAME"
echo "  Ferma:    sudo systemctl stop $SERVICE_NAME"
echo "  Stato:    sudo systemctl status $SERVICE_NAME"
echo "  Log:      sudo journalctl -u $SERVICE_NAME -f"
echo ""
echo "Modifica $CONFIG_FILE per personalizzare la configurazione"
echo "Riavvia il servizio dopo le modifiche: sudo systemctl restart $SERVICE_NAME"
echo ""

# Chiedi se avviare subito
read -p "Avviare il servizio ora? (y/n): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    systemctl start "$SERVICE_NAME"
    echo "Servizio avviato!"
    echo "Controlla lo stato con: sudo systemctl status $SERVICE_NAME"
fi