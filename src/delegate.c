#include "types.h"
#include "hashcat.h"
#include "common.h"
#include "user_options.h"
#include "delegate.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>

int delegate_session(hashcat_ctx_t *hashcat_ctx)
{
    user_options_t *user_options = hashcat_ctx->user_options;

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;

    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(DELEGATE_SERVER_PORT);
    
    if (inet_pton(AF_INET, DELEGATE_SERVER_IP, &serv_addr.sin_addr) <= 0) {
        close(sock);
        return -1;
    }

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        close(sock);
        return -1;
    }

    char cmd[4096];
    snprintf(cmd, sizeof(cmd),
        "hashcat --potfile-disable --restore-disable --attack-mode 3 -d %s "
        "--workload-profile 3 --optimized-kernel-enable --hash-type %d --hex-salt "
        "-1 \"?l?d?u\" --outfile-format 2 --quiet %s \"%s\"",
        user_options->backend_devices ? user_options->backend_devices : "1",
        user_options->hash_mode,
        user_options->hc_bin,
        user_options->custom_charset_1
    );

    send(sock, cmd, strlen(cmd), 0);

    char buffer[4096];
    int bytes;
    while ((bytes = recv(sock, buffer, sizeof(buffer)-1, 0)) > 0) {
        buffer[bytes] = '\0';
        printf("%s", buffer);
    }

    close(sock);
    return 0;
}