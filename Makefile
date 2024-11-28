# ----------------------------------------------------------
#   LNID - Local Network Identity Discovery
#
#   Make file - GCC compiler
#
# Copyright (c) 2024 Antonio Franco
#
# Questo programma è rilasciato sotto la licenza Creative Commons Attribuzione 4.0 Internazionale (CC BY 4.0).
# Puoi condividere, copiare, distribuire e modificare il programma, a condizione di dare il dovuto credito all'autore originale.
#
# Licenza completa: https://creativecommons.org/licenses/by/4.0/
# 
# auth. A.Franco - INFN Bary Italy
# date: 28/11/2024       ver.1.0
#
# ---------------------------------------------------------
#  HISTORY 
#  28/11/2024  -  Creation
#
# ---------------------------------------------------------

# Variabili
CC = gcc
CFLAGS = -Wall -Wextra -g
SRC_DIR = src
BUILD_DIR = build
INSTALL_DIR = /usr/local/bin

PROGRAMS = lnidd lnid-cli lnid-scan lnid-search

# Percorsi per gli eseguibili
TARGETS = $(addprefix $(BUILD_DIR)/, $(PROGRAMS))

# Target principale
all: $(BUILD_DIR) $(TARGETS)

# Regola per compilare ciascun programma
$(BUILD_DIR)/%: $(SRC_DIR)/%.c
	@echo "Compilazione di $< -> $@"
	$(CC) $(CFLAGS) -o $@ $<

# Regola per creare la directory degli eseguibili
$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)

# Regola per installare gli eseguibili
install: $(TARGETS)
	@echo "Installazione dei programmi in $(INSTALL_DIR)..."
	@for prog in $(PROGRAMS); do \
		echo "Installazione di $$prog..."; \
		sudo cp $(BUILD_DIR)/$$prog $(INSTALL_DIR)/; \
		sudo chmod 755 $(INSTALL_DIR)/$$prog; \
	done
	@echo "Installazione completata!"

# Pulizia
clean:
	rm -rf $(BUILD_DIR)

# Phony targets
.PHONY: all clean

