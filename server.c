#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <cjson/cJSON.h>
#include <fcntl.h>

#define BUFFER_SIZE 1024

// Struttura per contenere la configurazione del server
typedef struct {
    int port;
    char allowed_ip[INET_ADDRSTRLEN];
    char ssl_certificate[256];
    char ssl_key[256];
    int max_connections;
    int timeout;
    int max_requests_per_minute;
} ServerConfig;

// Funzione per validare l'input ricevuto
int validate_input(char *input) {
    if (strlen(input) > 100) {
        return 0; // Input non valido
    }
    return 1; // Input valido
}

// Funzione per gestire gli errori senza rivelare dettagli sensibili
void handle_error(const char *msg) {
    fprintf(stderr, "Errore: %s\n", msg);
    exit(EXIT_FAILURE);
}

// Funzione per leggere il file JSON di configurazione
ServerConfig read_config(const char *filename) {
    ServerConfig config;

    FILE *file = fopen(filename, "r");
    if (!file) {
        handle_error("Impossibile aprire il file di configurazione.");
    }

    fseek(file, 0, SEEK_END);
    long length = ftell(file);
    fseek(file, 0, SEEK_SET);

    char *data = (char *)malloc(length + 1);
    fread(data, 1, length, file);
    fclose(file);

    cJSON *json = cJSON_Parse(data);
    if (!json) {
        free(data);
        handle_error("Errore nel parsing del JSON.");
    }

    cJSON *server = cJSON_GetObjectItem(json, "server");
    config.port = cJSON_GetObjectItem(server, "port")->valueint;
    strcpy(config.allowed_ip, cJSON_GetObjectItem(server, "allowed_ip")->valuestring);
    strcpy(config.ssl_certificate, cJSON_GetObjectItem(server, "ssl_certificate")->valuestring);
    strcpy(config.ssl_key, cJSON_GetObjectItem(server, "ssl_key")->valuestring);
    config.max_connections = cJSON_GetObjectItem(server, "max_connections")->valueint;
    config.timeout = cJSON_GetObjectItem(server, "resource_limits")->child->valueint;
    config.max_requests_per_minute = cJSON_GetObjectItem(server, "resource_limits")->next->valueint;

    cJSON_Delete(json);
    free(data);

    return config;
}

// Inizializzazione SSL
SSL_CTX* init_ssl_context(ServerConfig *config) {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    OpenSSL_add_ssl_algorithms();
    method = TLS_server_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Errore creazione contesto SSL");
        exit(EXIT_FAILURE);
    }

    // Carica certificato e chiave privata
    if (SSL_CTX_use_certificate_file(ctx, config->ssl_certificate, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, config->ssl_key, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

// Funzione per creare il socket e avviare il server
int create_server_socket(ServerConfig *config) {
    int server_fd;
    struct sockaddr_in address;

    // Crea il socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Creazione socket fallita");
        exit(EXIT_FAILURE);
    }

    // Configura l'indirizzo del server
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(config->port);

    // Associa il socket all'indirizzo
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Bind fallito");
        exit(EXIT_FAILURE);
    }

    // Limita il numero di connessioni
    if (listen(server_fd, config->max_connections) < 0) {
        perror("Listen fallito");
        exit(EXIT_FAILURE);
    }

    return server_fd;
}

// Funzione per verificare l'indirizzo IP autorizzato
int is_ip_allowed(const char *ip, ServerConfig *config) {
    return strcmp(ip, config->allowed_ip) == 0;
}

// Main del server
int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Uso: %s <file_config.json>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    // Leggi la configurazione dal file JSON
    ServerConfig config = read_config(argv[1]);

    // Inizializza SSL
    SSL_CTX *ctx = init_ssl_context(&config);

    // Crea il socket del server
    int server_fd = create_server_socket(&config);

    printf("Server sicuro in ascolto sulla porta %d...\n", config.port);

    struct sockaddr_in client_addr;
    int addr_len = sizeof(client_addr);
    char client_ip[INET_ADDRSTRLEN];
    SSL *ssl;

    while (1) {
        int client_socket = accept(server_fd, (struct sockaddr *)&client_addr, (socklen_t *)&addr_len);
        if (client_socket < 0) {
            perror("Connessione fallita");
            continue;
        }

        // Converti l'IP del client in formato leggibile
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
        printf("Connessione da: %s\n", client_ip);

        // Controlla se l'IP del client è autorizzato
        if (!is_ip_allowed(client_ip, &config)) {
            printf("Connessione da %s bloccata!\n", client_ip);
            close(client_socket);
            continue;
        }

        // Inizializza SSL per la connessione
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_socket);

        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            close(client_socket);
            SSL_free(ssl);
            continue;
        }

        // Esegui la comunicazione sicura (HTTPS/WebSockets)
        char buffer[BUFFER_SIZE] = {0};
        int bytes = SSL_read(ssl, buffer, sizeof(buffer));
        if (bytes > 0) {
            buffer[bytes] = '\0';
            printf("Richiesta ricevuta: %s\n", buffer);

            // Risposta sicura al client
            char *response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nCiao dal server sicuro!\n";
            SSL_write(ssl, response, strlen(response));
        }

        // Chiudi la connessione
        SSL_free(ssl);
        close(client_socket);
    }

    // Libera le risorse SSL
    close(server_fd);
    SSL_CTX_free(ctx);
    EVP_cleanup();

    return 0;
}
