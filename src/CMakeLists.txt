cmake_minimum_required(VERSION 3.10)

# Nome del progetto
project(lnid_project LANGUAGES C)

# Imposta il livello di debug
set(CMAKE_BUILD_TYPE Debug)

# Aggiungi directory per i file di intestazione
include_directories(${CMAKE_SOURCE_DIR})

# Trova OpenSSL
find_package(OpenSSL REQUIRED)

if(NOT OpenSSL_FOUND)
    message(FATAL_ERROR "OpenSSL non trovato!")
endif()

# Aggiungi i file sorgenti
set(SOURCES
    lnidd.c
    lnid-cli.c
    lnid-scan.c
    lnid-search.c
    lnid-resolver.c
    lnid-hosts.c
)

# Aggiungi i target eseguibili e collega le librerie OpenSSL
foreach(file ${SOURCES})
    get_filename_component(target_name ${file} NAME_WE) # Rimuove estensione
    add_executable(${target_name} ${file})
    target_link_libraries(${target_name} OpenSSL::SSL OpenSSL::Crypto)
    target_include_directories(${target_name} PRIVATE ${CMAKE_SOURCE_DIR})
endforeach()

# Messaggio finale
message(STATUS "Configurazione completata!")
