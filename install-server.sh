#!/bin/bash

# ----------------------------------------------------------
#   LNID - Local Network Identity Discovery
#
#   BASH script to install the daemon as Linux service
#
# Copyright (c) 2024 Antonio Franco
#
# Questo programma è rilasciato sotto la licenza Creative Commons Attribuzione 4.0 Internazionale (CC BY 4.0).
# Puoi condividere, copiare, distribuire e modificare il programma, a condizione di dare il dovuto credito all'autore originale.
#
# Licenza completa: https://creativecommons.org/licenses/by/4.0/
# 
# auth. A.Franco - INFN Bary Italy
# date: 28/11/2024       ver.1.1
#
# ---------------------------------------------------------
#  HISTORY 
#  28/11/2024  -  Creation
#
# ---------------------------------------------------------

# Nome del programma e del servizio
SERVICE_NAME="lnid"
EXEC_PATH="/usr/local/bin/lnidd"
SERVICE_FILE="/etc/systemd/system/$SERVICE_NAME.service"
CONFIG_FILE="/etc/lnid-server.conf"

# Funzione per stampare un messaggio di errore e uscire
function error_exit {
    echo "$1" 1>&2
    exit 1
}

# Controllo privilegi root
if [ "$EUID" -ne 0 ]; then
    error_exit "Errore: sono necessari privilegi root per l'installazione"
fi

# Verifica che il programma esista
if [ ! -f "$EXEC_PATH" ]; then
    error_exit "Errore: il programma $EXEC_PATH non esiste!"
fi

# Ottieni hostname corrente per default
CURRENT_HOSTNAME=$(hostname)

# Crea file di configurazione
echo "Creazione file di configurazione..."
cat > "$CONFIG_FILE" <<EOL
# LNID Server Configuration
# Interfaccia ethernet da utilizzare
ETHERNET=eth0

# Porta UDP di ascolto
PORT=16969

# Hostname personalizzato (vuoto = usa hostname sistema)
HOSTNAME=$CURRENT_HOSTNAME

# Modalità cifrata (0=no, 1=si)
ENCRYPTED=0

# Modalità sicura - controllo accesso (0=no, 1=si)
SECURE_MODE=1

# Modalità verbose (0=no, 1=si)
VERBOSE=0
EOL

# Creazione del file di servizio systemd
echo "Creazione del file di servizio systemd in $SERVICE_FILE..."

cat > "$SERVICE_FILE" <<EOL
[Unit]
Description=LNID Server - Local Network Identity Discovery
Documentation=https://github.com/fapfap69/lnid
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStart=/bin/bash -c 'source $CONFIG_FILE && $EXEC_PATH -e \$ETHERNET -p \$PORT \$([ -n "\$HOSTNAME" ] && echo "-n \$HOSTNAME") \$([ \$ENCRYPTED -eq 1 ] && echo "-c") \$([ \$SECURE_MODE -eq 0 ] && echo "-s") \$([ \$VERBOSE -eq 1 ] && echo "-v")'
ExecReload=/bin/kill -HUP \$MAINPID
KillMode=process
Restart=on-failure
RestartSec=10
User=nobody
Group=nogroup

# Sicurezza
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOL

# Impostazioni dei permessi
chmod 644 "$SERVICE_FILE"
chmod 600 "$CONFIG_FILE"

# Ricarica systemd per rilevare il nuovo servizio
echo "Ricaricamento di systemd..."
systemctl daemon-reload

# Abilitazione del servizio (si avvia automaticamente all'avvio del sistema)
echo "Abilitazione del servizio..."
systemctl enable "$SERVICE_NAME"

# Avvia il servizio
echo "Avvio del servizio..."
systemctl start "$SERVICE_NAME"

# Verifica lo stato del servizio
echo "Stato del servizio $SERVICE_NAME:"
systemctl status "$SERVICE_NAME"

echo ""
echo "=== LNID Server installato con successo ==="
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
