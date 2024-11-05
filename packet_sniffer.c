#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <libpq-fe.h>
#include <netinet/in.h>

#define SNAP_LEN 1518
#define CONFIG_FILE "config.txt"

// Структуры
typedef struct {
    char dbname[256];
    char user[256];
    char password[256];
    char host[256];
    char port[6];
} DBConfig;

typedef struct {
    PGconn *conn;
} Database;

typedef struct {
    char source_mac[18];
    char destination_mac[18];
    char source_ip[16];
    char destination_ip[16];
    uint8_t protocol;
    uint32_t length;
} PacketInfo;

typedef struct {
    Database *db;
    pcap_t *handle;
    char *filter_ip;
} PacketCapture;

// Интерфейс для работы с базой данных
typedef struct {
    Database* (*connect)(const DBConfig *config);
    void (*insert_packet_data)(Database *db, const PacketInfo *packet_info);
    void (*cleanup)(Database *db);
} DBInterface;

// Интерфейс для захвата пакетов
typedef struct {
    void (*start_capture)(PacketCapture *capture);
    void (*cleanup)(PacketCapture *capture);
} PacketCaptureInterface;

// Загрузка конфигурации DB
DBConfig* load_db_config(const char *filename) {
    DBConfig *config = malloc(sizeof(DBConfig));
    if (!config) {
        fprintf(stderr, "Memory allocation failed\n");
        return NULL;
    }

    FILE *file = fopen(filename, "r");
    if (!file) {
        fprintf(stderr, "Could not open config file: %s\n", filename);
        free(config);
        return NULL;
    }

    memset(config, 0, sizeof(DBConfig));
    fscanf(file, "dbname=%255[^\n]\n", config->dbname);
    fscanf(file, "user=%255[^\n]\n", config->user);
    fscanf(file, "password=%255[^\n]\n", config->password);
    fscanf(file, "host=%255[^\n]\n", config->host);
    fscanf(file, "port=%5[^\n]\n", config->port);
    fclose(file);
    return config;
}

// Подключение к DB
Database* db_connect(const DBConfig *config) {
    Database *db = malloc(sizeof(Database));
    if (!db) return NULL;

    char conninfo[1536];
    snprintf(conninfo, sizeof(conninfo), "dbname=%s user=%s password=%s host=%s port=%s", 
             config->dbname, config->user, config->password, config->host, config->port);
    
    db->conn = PQconnectdb(conninfo);
    if (PQstatus(db->conn) != CONNECTION_OK) {
        fprintf(stderr, "Connection to database failed: %s\n", PQerrorMessage(db->conn));
        PQfinish(db->conn);
        free(db);
        return NULL;
    }

    const char *prepare_query = 
        "INSERT INTO packets (source_mac, destination_mac, source_ip, destination_ip, protocol, packet_length) "
        "VALUES ($1, $2, $3, $4, $5, $6);";
    
    PGresult *res = PQprepare(db->conn, "insert_packet", prepare_query, 0, NULL);
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "Preparation of SQL statement failed: %s", PQerrorMessage(db->conn));
        PQclear(res);
        PQfinish(db->conn);
        free(db);
        return NULL;
    }
    PQclear(res);
    return db;
}

// Запись данных о пакете в DB
void db_insert_packet_data(Database *db, const PacketInfo *packet_info) {
    const char *paramValues[6];
    
    paramValues[0] = packet_info->source_mac;
    paramValues[1] = packet_info->destination_mac;
    paramValues[2] = packet_info->source_ip;
    paramValues[3] = packet_info->destination_ip;

    char protocol[4], length[11];
    snprintf(protocol, sizeof(protocol), "%d", packet_info->protocol);
    snprintf(length, sizeof(length), "%d", packet_info->length);
    
    paramValues[4] = protocol;
    paramValues[5] = length;

    PGresult *res = PQexecPrepared(db->conn, "insert_packet", 6, paramValues, NULL, NULL, 0);
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "Insert failed: %s", PQerrorMessage(db->conn));
    }
    PQclear(res);
}

// Очистка ресурсов DB
void db_cleanup(Database *db) {
    if (db) {
        PQfinish(db->conn);
        free(db);
    }
}

// Создание информации о пакете
void build_packet_info(const struct pcap_pkthdr *header, const u_char *packet, PacketInfo *packet_info) {
    struct ether_header *eth_header = (struct ether_header *)packet;
    struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
    
    snprintf(packet_info->source_mac, sizeof(packet_info->source_mac), "%s", ether_ntoa((struct ether_addr *)eth_header->ether_shost));
    snprintf(packet_info->destination_mac, sizeof(packet_info->destination_mac), "%s", ether_ntoa((struct ether_addr *)eth_header->ether_dhost));
    snprintf(packet_info->source_ip, sizeof(packet_info->source_ip), "%s", inet_ntoa(ip_header->ip_src));
    snprintf(packet_info->destination_ip, sizeof(packet_info->destination_ip), "%s", inet_ntoa(ip_header->ip_dst));
    
    packet_info->protocol = ip_header->ip_p;
    packet_info->length = ntohs(ip_header->ip_len);
}

// Фильтрация пакетов по IP
int should_filter_packet(const char *ip, const char *filter_ip) {
    return strcmp(ip, filter_ip) == 0;
}

// Обработчик пакетов
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    PacketCapture *capture = (PacketCapture *)args;
    PacketInfo packet_info;
    
    build_packet_info(header, packet, &packet_info);
    
    if (should_filter_packet(packet_info.source_ip, capture->filter_ip) || 
        should_filter_packet(packet_info.destination_ip, capture->filter_ip)) {
        return; // Пропустить пакет, если он от фильтруемого IP
    }
    
    printf("inser data -> %p - %p\n", packet_info.source_ip, packet_info.destination_ip);

    db_insert_packet_data(capture->db, &packet_info);
}

// Запуск захвата пакетов
void start_capture(PacketCapture *capture) {
    char errbuf[PCAP_ERRBUF_SIZE];
    capture->handle = pcap_open_live("eth0", SNAP_LEN, 1, 1000, errbuf);
    if (capture->handle == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", "eth0", errbuf);
        return;
    }
    
    pcap_loop(capture->handle, 0, packet_handler, (u_char *)capture);
}

// Очистка ресурсов захвата пакетов
void packet_capture_cleanup(PacketCapture *capture) {
    if (capture->handle) {
        pcap_close(capture->handle);
    }
    db_cleanup(capture->db);
}

int main() {
    DBConfig *config = load_db_config(CONFIG_FILE);
    if (!config) return EXIT_FAILURE;

    Database *db = db_connect(config);
    free(config);
    if (!db) return EXIT_FAILURE;

    PacketCapture capture = { .db = db, .filter_ip = "192.168.0.252" }; // IP адрес исключения
    start_capture(&capture);
    
    packet_capture_cleanup(&capture);
    return EXIT_SUCCESS;
}