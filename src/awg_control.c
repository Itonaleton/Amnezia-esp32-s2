/*
 * AmneziaWG control over the ESP console (UART). Config lives in RAM only.
 *
 * Commands:
 *   awg_param <key> <value>   privkey pubkey psk ip endpoint port jc jmin jmax s1 s2 s3 s4 h1..h4
 *   awg_i1 clear              clear the I1 template
 *   awg_i1 add "<chunk>"      append a chunk of the I1 template (may be called many times)
 *   awg_up                    sync time, bring tunnel up, make it the default route
 *   awg_down                  tunnel down, restore the direct route
 *   awg_wipe                  tunnel down + erase all keys/params from RAM
 *   awg_status
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>
#include "esp_log.h"
#include "esp_console.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_sntp.h"
#include "esp_wireguard.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "mbedtls/platform_util.h"
#include "awg.h"

static const char *TAG = "awg_ctrl";

static struct {
    char privkey[64];
    char pubkey[64];
    char psk[64];
    char ip[20];
    char endpoint[96];
    int  port;
} cfg = { .port = 51820 };

/* esp_wireguard keeps a pointer to the config, so it must stay alive */
static wireguard_config_t wg_config;
static wireguard_ctx_t wg_ctx;
static bool wg_active = false;
static bool handler_registered = false;

static void copy_str(char *dst, size_t dst_size, const char *src)
{
    strncpy(dst, src, dst_size - 1);
    dst[dst_size - 1] = '\0';
}

static bool ensure_time(void)
{
    const time_t valid_after = 1700000000; /* Nov 2023 */
    if (time(NULL) > valid_after) {
        return true;
    }
    if (!esp_sntp_enabled()) {
        esp_sntp_setoperatingmode(ESP_SNTP_OPMODE_POLL);
        esp_sntp_setservername(0, "pool.ntp.org");
        esp_sntp_setservername(1, "time.google.com");
        esp_sntp_init();
    }
    for (int i = 0; i < 75; i++) { /* up to 15 s */
        if (time(NULL) > valid_after) {
            return true;
        }
        vTaskDelay(pdMS_TO_TICKS(200));
    }
    return false;
}

/* esp_netif recomputes netif_default on every uplink GOT_IP (DHCP renewals too),
 * so re-assert the tunnel as default route while it is up. */
static void ip_event_cb(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    if (wg_active && wg_ctx.netif) {
        esp_wireguard_set_default(&wg_ctx);
    }
}

static int cmd_awg_param(int argc, char **argv)
{
    if (argc < 3) {
        printf("Usage: awg_param <key> <value>\n");
        return 1;
    }
    const char *k = argv[1];
    const char *v = argv[2];

    if (!strcmp(k, "privkey"))        copy_str(cfg.privkey, sizeof(cfg.privkey), v);
    else if (!strcmp(k, "pubkey"))    copy_str(cfg.pubkey, sizeof(cfg.pubkey), v);
    else if (!strcmp(k, "psk"))       copy_str(cfg.psk, sizeof(cfg.psk), v);
    else if (!strcmp(k, "ip"))        copy_str(cfg.ip, sizeof(cfg.ip), v);
    else if (!strcmp(k, "endpoint"))  copy_str(cfg.endpoint, sizeof(cfg.endpoint), v);
    else if (!strcmp(k, "port"))      cfg.port = atoi(v);
    else if (awg_set_param(k, v) != 0) {
        printf("AWG_ERROR: BAD_PARAM %s\n", k);
        return 1;
    }
    printf("AWG_PARAM_OK: %s\n", k);
    return 0;
}

static int cmd_awg_i1(int argc, char **argv)
{
    if (argc >= 2 && !strcmp(argv[1], "clear")) {
        awg_i1_clear();
        printf("AWG_I1_OK: cleared\n");
        return 0;
    }
    if (argc >= 3 && !strcmp(argv[1], "add")) {
        if (awg_i1_append(argv[2]) != 0) {
            printf("AWG_ERROR: I1_TOO_LONG\n");
            return 1;
        }
        printf("AWG_I1_OK: %u\n", (unsigned)strlen(g_awg.i1));
        return 0;
    }
    printf("Usage: awg_i1 clear | awg_i1 add \"<chunk>\"\n");
    return 1;
}

static int cmd_awg_up(int argc, char **argv)
{
    if (wg_active) {
        printf("AWG_STATUS: ALREADY_RUNNING\n");
        return 0;
    }
    if (!cfg.privkey[0] || !cfg.pubkey[0] || !cfg.ip[0] || !cfg.endpoint[0]) {
        printf("AWG_ERROR: MISSING_PARAMS (need privkey pubkey ip endpoint)\n");
        return 1;
    }
    if (!ensure_time()) {
        printf("AWG_ERROR: NO_TIME (is the uplink Wi-Fi connected?)\n");
        return 1;
    }

    wireguard_config_t tmp = ESP_WIREGUARD_CONFIG_DEFAULT();
    wg_config = tmp;
    wg_config.private_key = cfg.privkey;
    wg_config.public_key = cfg.pubkey;
    wg_config.preshared_key = cfg.psk[0] ? cfg.psk : NULL;
    wg_config.allowed_ip = cfg.ip;
    wg_config.allowed_ip_mask = "255.255.255.0";
    wg_config.endpoint = cfg.endpoint;
    wg_config.port = cfg.port;
    wg_config.persistent_keepalive = 25;

    memset(&wg_ctx, 0, sizeof(wg_ctx));
    if (esp_wireguard_init(&wg_config, &wg_ctx) != ESP_OK) {
        printf("AWG_ERROR: INIT_FAILED\n");
        return 1;
    }
    if (esp_wireguard_connect(&wg_ctx) != ESP_OK) {
        printf("AWG_ERROR: CONNECT_FAILED\n");
        esp_wireguard_disconnect(&wg_ctx);
        return 1;
    }

    /* wait for the handshake to complete */
    bool up = false;
    for (int i = 0; i < 100; i++) { /* up to 20 s */
        if (esp_wireguardif_peer_is_up(&wg_ctx) == ESP_OK) {
            up = true;
            break;
        }
        vTaskDelay(pdMS_TO_TICKS(200));
    }
    if (!up) {
        esp_wireguard_disconnect(&wg_ctx);
        printf("AWG_ERROR: HANDSHAKE_TIMEOUT\n");
        return 1;
    }

    esp_wireguard_set_default(&wg_ctx);
    wg_active = true;

    if (!handler_registered) {
        if (esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &ip_event_cb, NULL) == ESP_OK) {
            handler_registered = true;
        }
    }
    printf("AWG_STATUS: CONNECTED\n");
    return 0;
}

static int cmd_awg_down(int argc, char **argv)
{
    if (!wg_active) {
        printf("AWG_STATUS: ALREADY_STOPPED\n");
        return 0;
    }
    wg_active = false;
    esp_wireguard_disconnect(&wg_ctx); /* restores the previous default netif */
    printf("AWG_STATUS: DISCONNECTED\n");
    return 0;
}

static int cmd_awg_wipe(int argc, char **argv)
{
    if (wg_active) {
        cmd_awg_down(0, NULL);
    }
    mbedtls_platform_zeroize(&cfg, sizeof(cfg));
    cfg.port = 51820;
    awg_wipe();
    printf("AWG_STATUS: RAM_WIPED\n");
    return 0;
}

static int cmd_awg_status(int argc, char **argv)
{
    bool up = wg_active && esp_wireguardif_peer_is_up(&wg_ctx) == ESP_OK;
    printf("AWG_STATUS: %s peer_up=%d time_ok=%d i1_len=%u\n",
           wg_active ? "ACTIVE" : "STOPPED", up, time(NULL) > 1700000000,
           g_awg.i1 ? (unsigned)strlen(g_awg.i1) : 0u);
    return 0;
}

/* Call from app_main() after register_router(); */
void register_awg_commands(void)
{
    const esp_console_cmd_t cmds[] = {
        { .command = "awg_param",  .help = "Set AmneziaWG parameter (RAM only)", .func = &cmd_awg_param },
        { .command = "awg_i1",     .help = "awg_i1 clear | add \"<chunk>\"",      .func = &cmd_awg_i1 },
        { .command = "awg_up",     .help = "Start AmneziaWG tunnel",             .func = &cmd_awg_up },
        { .command = "awg_down",   .help = "Stop tunnel, restore direct route",  .func = &cmd_awg_down },
        { .command = "awg_wipe",   .help = "Stop tunnel and wipe RAM config",    .func = &cmd_awg_wipe },
        { .command = "awg_status", .help = "Show tunnel status",                 .func = &cmd_awg_status },
    };
    for (size_t i = 0; i < sizeof(cmds) / sizeof(cmds[0]); i++) {
        ESP_ERROR_CHECK(esp_console_cmd_register(&cmds[i]));
    }
    ESP_LOGI(TAG, "AmneziaWG commands registered");
}
