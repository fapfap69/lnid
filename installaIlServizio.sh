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

# Funzione per stampare un messaggio di errore e uscire
function error_exit {
    echo "$1" 1>&2
    exit 1
}

# Verifica che il programma esista
if [ ! -f "$EXEC_PATH" ]; then
    error_exit "Errore: il programma $EXEC_PATH non esiste!"
fi

# Creazione del file di servizio systemd
echo "Creazione del file di servizio systemd in $SERVICE_FILE..."

cat > "$SERVICE_FILE" <<EOL
[Unit]
Description=Servizio per $SERVICE_NAME
After=network.target

[Service]
ExecStart=$EXEC_PATH
Restart=always
User=nobody
Group=nogroup

[Install]
WantedBy=multi-user.target
EOL

# Impostazioni dei permessi per il file di servizio
chmod 644 "$SERVICE_FILE"

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

echo "Installazione completata!"
