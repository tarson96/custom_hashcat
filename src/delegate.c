#include "types.h"
#include "hashcat.h"
#include "common.h"
#include "user_options.h"
#include "delegate.h"
#include "shared.h"
#include "memory.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <dirent.h>
#include <sys/types.h>
#include <syslog.h>
#include <time.h>

static void log_to_file(const char *message) {
    FILE *log_file = fopen("/root/app/delegate.log", "a");
    if (log_file != NULL) {
        time_t now = time(NULL);
        char timestamp[64];
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));
        fprintf(log_file, "[%s] %s\n", timestamp, message);
        fclose(log_file);
    }
}

int delegate_session(hashcat_ctx_t *hashcat_ctx)
{
    char log_msg[1024];
    log_to_file("Delegate session started");

    if (hashcat_ctx == NULL) {
        log_to_file("Error: hashcat_ctx is NULL");
        return -1;
    }

    user_options_t *user_options = hashcat_ctx->user_options;
    if (user_options == NULL) {
        log_to_file("Error: user_options is NULL");
        return -1;
    }

    snprintf(log_msg, sizeof(log_msg), "Hash mode: %d", user_options->hash_mode);
    log_to_file(log_msg);

    // Find .txt file in /root/app/temp
    DIR *dir;
    struct dirent *ent;
    char payload_path[4096] = {0};
    
    log_to_file("Attempting to open directory /root/app/temp");
    dir = opendir("/root/app/temp");
    if (dir != NULL) {
        log_to_file("Directory opened successfully");
        while ((ent = readdir(dir)) != NULL) {
            if (strstr(ent->d_name, ".txt") != NULL) {
                snprintf(payload_path, sizeof(payload_path), "/root/app/temp/%s", ent->d_name);
                snprintf(log_msg, sizeof(log_msg), "Found payload file: %s", payload_path);
                log_to_file(log_msg);
                break;
            }
        }
        closedir(dir);
    } else {
        log_to_file("Failed to open directory /root/app/temp");
        return -1;
    }

    if (payload_path[0] == 0) {
        log_to_file("No .txt file found in /root/app/temp");
        return -1;
    }

    // Network connection
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        log_to_file("Failed to create socket");
        return -1;
    }

    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(DELEGATE_SERVER_PORT);
    
    snprintf(log_msg, sizeof(log_msg), "Attempting to connect to %s:%d", DELEGATE_SERVER_IP, DELEGATE_SERVER_PORT);
    log_to_file(log_msg);

    if (inet_pton(AF_INET, DELEGATE_SERVER_IP, &serv_addr.sin_addr) <= 0) {
        log_to_file("Invalid address");
        close(sock);
        return -1;
    }

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        log_to_file("Connection failed");
        close(sock);
        return -1;
    }

    log_to_file("Connected successfully");

    // Construct command
    char cmd[4096];
    snprintf(cmd, sizeof(cmd),
        "hashcat --potfile-disable --restore-disable --attack-mode 3 -d %s "
        "--workload-profile 3 --optimized-kernel-enable --hash-type %d "
        "-1 \"?l?d?u\" --outfile-format 2 --quiet %s \"%s\"",
        user_options->backend_devices ? user_options->backend_devices : "1",
        user_options->hash_mode,
        payload_path,
        user_options->custom_charset_1
    );

    snprintf(log_msg, sizeof(log_msg), "Executing command: %s", cmd);
    log_to_file(log_msg);

    // Send command
    size_t cmd_len = strlen(cmd);
    ssize_t sent = send(sock, cmd, cmd_len, 0);
    if (sent != cmd_len) {
        log_to_file("Failed to send complete command");
        close(sock);
        return -1;
    }

    log_to_file("Command sent successfully");

    // Receive response
    char buffer[4096];
    int bytes;
    while ((bytes = recv(sock, buffer, sizeof(buffer)-1, 0)) > 0) {
        buffer[bytes] = '\0';
        printf("%s", buffer);  // Print to stdout
        
        // Log response chunks
        snprintf(log_msg, sizeof(log_msg), "Received response chunk: %d bytes", bytes);
        log_to_file(log_msg);
    }

    if (bytes < 0) {
        log_to_file("Error receiving response");
    }

    log_to_file("Delegate session completed");
    close(sock);
    return 0;
}