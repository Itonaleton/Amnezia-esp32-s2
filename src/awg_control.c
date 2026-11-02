#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "esp_log.h"
#include "esp_console.h"
#include "esp_wireguard.h"
#include "lwip/netif.h"
#include "lwip/lwip_napt.h"
#include "mbedtls/platform_util.h"

static const char *TAG = "awg_ctrl";

// Структура параметров обфускации AmneziaWG (читается в wireguardif.c)
typedef struct {
    char privkey[64];
    char pubkey[64];
    char ip[32];
    char endpoint[64];
    int port;
    uint16_t jc;
    uint16_t jmin;
    uint16_t jmax;
    uint16_t s1;
    uint16_t s2;
    uint32_t h1;
    uint32_t h2;
    uint32_t h3;
    uint32_t h4;
} awg_runtime_params_t;

// Глобальная конфигурация только в RAM (не сохраняется во Flash/NVS)
awg_runtime_params_t g_awg_cfg = {
    .port = 51820,
    .jc = 4, .jmin = 40, .jmax = 70,
    .s1 = 15, .s2 = 18,
    .h1 = 1, .h2 = 2, .h3 = 3, .h4 = 4
};

static wireguard_ctx_t wg_ctx = {0};
static bool wg_active = false;
static struct netif *orig_default_netif = NULL;

// Команда: awg_param key value
static int cmd_awg_param(int argc, char **argv) {
    if (argc < 3) {
        printf("Usage: awg_param [key] [value]\n");
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
    else if (strcmp(k, "h1") == 0) g_awg_cfg.h1 = (uint32_t)strtoul(v, NULL, 10);
    else if (strcmp(k, "h2") == 0) g_awg_cfg.h2 = (uint32_t)strtoul(v, NULL, 10);
    else if (strcmp(k, "h3") == 0) g_awg_cfg.h3 = (uint32_t)strtoul(v, NULL, 10);
    else if (strcmp(k, "h4") == 0) g_awg_cfg.h4 = (uint32_t)strtoul(v, NULL, 10);

    printf("AWG_PARAM_OK: %s\n", k);
    return 0;
}

// Команда: awg_up (запуск туннеля и переключение NAT)
static int cmd_awg_up(int argc, char **argv) {
    if (wg_active) {
        printf("AWG_STATUS: ALREADY_RUNNING\n");
        return 0;
    }

    wireguard_config_t wg_config = ESP_WIREGUARD_CONFIG_DEFAULT();
    wg_config.private_key = g_awg_cfg.privkey;
    wg_config.public_key = g_awg_cfg.pubkey;
    wg_config.address = g_awg_cfg.ip;
    wg_config.netmask = "255.255.255.0";
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

    // Ищем поднятый интерфейс wg0 в списке lwIP и включаем на нем NAPT
    struct netif *netif;
    NETIF_FOREACH(netif) {
        if (netif->name[0] == 'w' && netif->name[1] == 'g') {
            netif_set_default(netif);
            ip_napt_enable(netif->ip_addr.u_addr.ip4.addr, 1);
            ESP_LOGI(TAG, "NAPT enabled on AWG interface");
            break;
        }
    }

    wg_active = true;
    printf("AWG_STATUS: CONNECTED\n");
    return 0;
}

// Команда: awg_down (отключение VPN, возврат к прямому репитеру)
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

// Команда: awg_wipe (безопасная очистка ключей из RAM платы)
static int cmd_awg_wipe(int argc, char **argv) {
    if (wg_active) {
        cmd_awg_down(0, NULL);
    }
    mbedtls_platform_zeroize(&g_awg_cfg, sizeof(g_awg_cfg));
    printf("AWG_STATUS: RAM_WIPED\n");
    return 0;
}

// Вызовите эту функцию в app_main() файла esp32_nat_router.c
void register_awg_commands(void) {
    const esp_console_cmd_t cmd_param = {
        .command = "awg_param",
        .help = "Set AmneziaWG parameter in RAM",
        .func = &cmd_awg_param,
    };
    const esp_console_cmd_t cmd_up = {
        .command = "awg_up",
        .help = "Start AmneziaWG tunnel and route NAT through it",
        .func = &cmd_awg_up,
    };
    const esp_console_cmd_t cmd_down = {
        .command = "awg_down",
        .help = "Stop AmneziaWG tunnel and restore direct NAT",
        .func = &cmd_awg_down,
    };
    const esp_console_cmd_t cmd_wipe = {
        .command = "awg_wipe",
        .help = "Wipe AmneziaWG config from RAM",
        .func = &cmd_awg_wipe,
    };

    esp_console_cmd_register(&cmd_param);
    esp_console_cmd_register(&cmd_up);
    esp_console_cmd_register(&cmd_down);
    esp_console_cmd_register(&cmd_wipe);
}
