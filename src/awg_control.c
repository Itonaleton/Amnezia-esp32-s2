#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "esp_log.h"
#include "esp_console.h"
#include "esp_sntp.h"
#include "esp_wireguard.h"
#include "lwip/netif.h"
#include "lwip/lwip_napt.h"
#include "mbedtls/platform_util.h"

static const char *TAG = "awg_ctrl";

typedef struct {
    char privkey[64];
    char pubkey[64];
    char ip[32];
    char endpoint[64];
    int port;
    uint16_t jc, jmin, jmax;
    uint16_t s1, s2, s3, s4;
    uint32_t h1, h2, h3, h4;
    char i1[1024]; // Буфер для CPS-пакета I1 (AmneziaWG 2.0)
} awg_runtime_params_t;

awg_runtime_params_t g_awg_cfg = {
    .port = 51820,
    .jc = 4, .jmin = 40, .jmax = 70,
    .s1 = 0, .s2 = 0, .s3 = 1274, .s4 = 12,
    .h1 = 1, .h2 = 2, .h3 = 3, .h4 = 4
};

static wireguard_ctx_t wg_ctx = {0};
static bool wg_active = false;
static bool sntp_started = false;
static struct netif *orig_default_netif = NULL;

static void ensure_sntp(void) {
    if (!sntp_started) {
        esp_sntp_setoperatingmode(SNTP_OPMODE_POLL);
        esp_sntp_setservername(0, "pool.ntp.org");
        esp_sntp_init();
        sntp_started = true;
    }
}

// Команда: awg_param <key> <value>
static int cmd_awg_param(int argc, char **argv) {
    if (argc < 3) {
        printf("Usage: awg_param <key> <value>\n");
        return 1;
    }
    const char *k = argv[1];
    const char *v = argv[2];

    if (strcmp(k, "privkey") == 0) strncpy(g_awg_cfg.privkey, v, sizeof(g_awg_cfg.privkey) - 1);
    else if (strcmp(k, "pubkey") == 0) strncpy(g_awg_cfg.pubkey, v, sizeof(g_awg_cfg.pubkey) - 1);
    else if (strcmp(k, "ip") == 0) strncpy(g_awg_cfg.ip, v, sizeof(g_awg_cfg.ip) - 1);
    else if (strcmp(k, "endpoint") == 0) strncpy(g_awg_cfg.endpoint, v, sizeof(g_awg_cfg.endpoint) - 1);
    else if (strcmp(k, "port") == 0) g_awg_cfg.port = atoi(v);
    else if (strcmp(k, "jc") == 0) g_awg_cfg.jc = (uint16_t)atoi(v);
    else if (strcmp(k, "jmin") == 0) g_awg_cfg.jmin = (uint16_t)atoi(v);
    else if (strcmp(k, "jmax") == 0) g_awg_cfg.jmax = (uint16_t)atoi(v);
    else if (strcmp(k, "s1") == 0) g_awg_cfg.s1 = (uint16_t)atoi(v);
    else if (strcmp(k, "s2") == 0) g_awg_cfg.s2 = (uint16_t)atoi(v);
    else if (strcmp(k, "s3") == 0) g_awg_cfg.s3 = (uint16_t)atoi(v);
    else if (strcmp(k, "s4") == 0) g_awg_cfg.s4 = (uint16_t)atoi(v);
    else if (strcmp(k, "h1") == 0) g_awg_cfg.h1 = (uint32_t)strtoul(v, NULL, 10);
    else if (strcmp(k, "h2") == 0) g_awg_cfg.h2 = (uint32_t)strtoul(v, NULL, 10);
    else if (strcmp(k, "h3") == 0) g_awg_cfg.h3 = (uint32_t)strtoul(v, NULL, 10);
    else if (strcmp(k, "h4") == 0) g_awg_cfg.h4 = (uint32_t)strtoul(v, NULL, 10);
    else if (strcmp(k, "i1_clear") == 0) g_awg_cfg.i1[0] = '\0';

    printf("AWG_PARAM_OK: %s\n", k);
    return 0;
}

// Команда: awg_i1_chunk <hex_or_text_chunk> (для поблочной передачи длинного I1 с Flipper)
static int cmd_awg_i1_chunk(int argc, char **argv) {
    if (argc < 2) return 1;
    size_t cur_len = strlen(g_awg_cfg.i1);
    size_t add_len = strlen(argv[1]);
    if (cur_len + add_len < sizeof(g_awg_cfg.i1) - 1) {
        strcat(g_awg_cfg.i1, argv[1]);
        printf("AWG_I1_LEN: %u\n", (unsigned)(cur_len + add_len));
    }
    return 0;
}

// Команда: awg_up
static int cmd_awg_up(int argc, char **argv) {
    if (wg_active) {
        printf("AWG_STATUS: ALREADY_RUNNING\n");
        return 0;
    }

    ensure_sntp();

    wireguard_config_t wg_config = ESP_WIREGUARD_CONFIG_DEFAULT();
    wg_config.private_key = g_awg_cfg.privkey;
    wg_config.public_key = g_awg_cfg.pubkey;
    wg_config.allowed_ip = g_awg_cfg.ip;
    wg_config.allowed_ip_mask = "255.255.255.0";
    wg_config.endpoint = g_awg_cfg.endpoint;
    wg_config.port = g_awg_cfg.port;
    wg_config.persistent_keepalive = 25;

    if (esp_wireguard_init(&wg_config, &wg_ctx) != ESP_OK) {
        printf("AWG_ERROR: INIT_FAILED\n");
        return 1;
    }

    orig_default_netif = netif_default;

    if (esp_wireguard_connect(&wg_ctx) != ESP_OK) {
        printf("AWG_ERROR: CONNECT_FAILED\n");
        return 1;
    }

    struct netif *netif;
    NETIF_FOREACH(netif) {
        if (netif->name[0] == 'w' && netif->name[1] == 'g') {
            netif_set_default(netif);
            ip_napt_enable(netif->ip_addr.u_addr.ip4.addr, 1);
            ESP_LOGI(TAG, "NAPT switched to wg interface");
            break;
        }
    }

    wg_active = true;
    printf("AWG_STATUS: CONNECTED\n");
    return 0;
}

// Команда: awg_down
static int cmd_awg_down(int argc, char **argv) {
    if (!wg_active) {
        printf("AWG_STATUS: ALREADY_STOPPED\n");
        return 0;
    }
    if (orig_default_netif != NULL) {
        netif_set_default(orig_default_netif);
    }
    esp_wireguard_disconnect(&wg_ctx);
    wg_active = false;
    printf("AWG_STATUS: DISCONNECTED\n");
    return 0;
}

// Команда: awg_wipe
static int cmd_awg_wipe(int argc, char **argv) {
    if (wg_active) {
        cmd_awg_down(0, NULL);
    }
    mbedtls_platform_zeroize(&g_awg_cfg, sizeof(g_awg_cfg));
    printf("AWG_STATUS: RAM_WIPED\n");
    return 0;
}

void register_awg_commands(void) {
    const esp_console_cmd_t cmds[] = {
        { .command = "awg_param",    .help = "Set AWG param in RAM",    .func = &cmd_awg_param },
        { .command = "awg_i1_chunk", .help = "Append I1 signature",     .func = &cmd_awg_i1_chunk },
        { .command = "awg_up",       .help = "Start AWG VPN tunnel",    .func = &cmd_awg_up },
        { .command = "awg_down",     .help = "Stop AWG VPN tunnel",     .func = &cmd_awg_down },
        { .command = "awg_wipe",     .help = "Wipe AWG config in RAM",  .func = &cmd_awg_wipe }
    };
    for (size_t i = 0; i < sizeof(cmds) / sizeof(cmds[0]); i++) {
        esp_console_cmd_register(&cmds[i]);
    }
}
