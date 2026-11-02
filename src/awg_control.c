#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include "esp_log.h"
#include "esp_console.h"
#include "esp_sntp.h"
#include "esp_random.h"
#include "esp_wireguard.h"
#include "lwip/netif.h"
#include "lwip/udp.h"
#include "lwip/dns.h"
#include "lwip/lwip_napt.h"
#include "mbedtls/platform_util.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "awg_ctrl";

typedef struct {
    char privkey[64];
    char pubkey[64];
    char psk[64];
    char ip[32];
    char endpoint[64];
    int port;
    uint16_t jc, jmin, jmax;
    uint16_t s1, s2, s3, s4;
    uint32_t h1_min, h1_max;
    uint32_t h2_min, h2_max;
    uint32_t h3_min, h3_max;
    uint32_t h4_min, h4_max;
    char i1[1024];
} awg_runtime_params_t;

awg_runtime_params_t g_awg_cfg = {
    .port = 51820,
    .jc = 4, .jmin = 40, .jmax = 70,
    .s1 = 0, .s2 = 0, .s3 = 0, .s4 = 0,
    .h1_min = 1, .h1_max = 1,
    .h2_min = 2, .h2_max = 2,
    .h3_min = 3, .h3_max = 3,
    .h4_min = 4, .h4_max = 4
};

static wireguard_ctx_t wg_ctx = {0};
static bool wg_active = false;
static bool sntp_started = false;
static struct netif *orig_default_netif = NULL;
static uint32_t awg_pkt_counter = 0;

/* --- Функции обфускации AmneziaWG 2.0 (вызываются из пропатченного esp_wireguard) --- */

static uint32_t awg_rand_range(uint32_t min_v, uint32_t max_v) {
    if (max_v <= min_v) return min_v;
    return min_v + (esp_random() % (max_v - min_v + 1));
}

static uint32_t awg_read_u32_le(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void awg_write_u32_le(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v & 0xFF);
    p[1] = (uint8_t)((v >> 8) & 0xFF);
    p[2] = (uint8_t)((v >> 16) & 0xFF);
    p[3] = (uint8_t)((v >> 24) & 0xFF);
}

void awg_write_h1(uint8_t *p) { awg_write_u32_le(p, awg_rand_range(g_awg_cfg.h1_min, g_awg_cfg.h1_max)); }
void awg_write_h2(uint8_t *p) { awg_write_u32_le(p, awg_rand_range(g_awg_cfg.h2_min, g_awg_cfg.h2_max)); }
void awg_write_h3(uint8_t *p) { awg_write_u32_le(p, awg_rand_range(g_awg_cfg.h3_min, g_awg_cfg.h3_max)); }
void awg_write_h4(uint8_t *p) { awg_write_u32_le(p, awg_rand_range(g_awg_cfg.h4_min, g_awg_cfg.h4_max)); }

bool awg_check_h1(const uint8_t *p) { uint32_t v = awg_read_u32_le(p); return (v >= g_awg_cfg.h1_min && v <= g_awg_cfg.h1_max); }
bool awg_check_h2(const uint8_t *p) { uint32_t v = awg_read_u32_le(p); return (v >= g_awg_cfg.h2_min && v <= g_awg_cfg.h2_max); }
bool awg_check_h3(const uint8_t *p) { uint32_t v = awg_read_u32_le(p); return (v >= g_awg_cfg.h3_min && v <= g_awg_cfg.h3_max); }
bool awg_check_h4(const uint8_t *p) { uint32_t v = awg_read_u32_le(p); return (v >= g_awg_cfg.h4_min && v <= g_awg_cfg.h4_max); }

/* Определение длины случайного префикса S1..S4 при отправке пакета */
uint16_t awg_get_tx_prefix_len(const uint8_t *data, size_t len) {
    if (len < 4) return 0;
    if (len == 148 && awg_check_h1(data)) return g_awg_cfg.s1;
    if (len == 92  && awg_check_h2(data)) return g_awg_cfg.s2;
    if (len == 64  && awg_check_h3(data)) return g_awg_cfg.s3;
    if (len >= 32  && awg_check_h4(data)) return g_awg_cfg.s4;
    return 0;
}

/* Удаление префикса S1..S4 при приёме пакета из сети */
void awg_strip_rx_prefix(uint8_t **data, size_t *len) {
    uint8_t *d = *data;
    size_t l = *len;
    if (l == (size_t)(g_awg_cfg.s1 + 148) && awg_check_h1(d + g_awg_cfg.s1)) {
        *data += g_awg_cfg.s1; *len -= g_awg_cfg.s1;
    } else if (l == (size_t)(g_awg_cfg.s2 + 92) && awg_check_h2(d + g_awg_cfg.s2)) {
        *data += g_awg_cfg.s2; *len -= g_awg_cfg.s2;
    } else if (l == (size_t)(g_awg_cfg.s3 + 64) && awg_check_h3(d + g_awg_cfg.s3)) {
        *data += g_awg_cfg.s3; *len -= g_awg_cfg.s3;
    } else if (l >= (size_t)(g_awg_cfg.s4 + 32) && awg_check_h4(d + g_awg_cfg.s4)) {
        *data += g_awg_cfg.s4; *len -= g_awg_cfg.s4;
    }
}

static int hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Сборка CPS-пакета I1 по шаблону тегов AmneziaWG 2.0 */
static size_t awg_build_i1_packet(uint8_t *out, size_t max_len) {
    const char *p = g_awg_cfg.i1;
    size_t out_len = 0;
    static const char alnum[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

    while (*p && out_len < max_len) {
        const char *lt = strchr(p, '<');
        if (!lt) break;
        const char *gt = strchr(lt, '>');
        if (!gt) break;

        const char *tag = lt + 1;
        while (*tag == ' ') tag++;

        if (strncmp(tag, "b ", 2) == 0 || strncmp(tag, "B ", 2) == 0) {
            const char *hx = strstr(tag, "0x");
            if (!hx) hx = strstr(tag, "0X");
            hx = hx ? (hx + 2) : (tag + 2);
            while (hx + 1 < gt && out_len < max_len) {
                if (*hx == ' ') { hx++; continue; }
                int hi = hex_val(hx[0]);
                int lo = hex_val(hx[1]);
                if (hi >= 0 && lo >= 0) {
                    out[out_len++] = (uint8_t)((hi << 4) | lo);
                    hx += 2;
                } else {
                    break;
                }
            }
        } else if (strncmp(tag, "rd ", 3) == 0) {
            int n = atoi(tag + 3);
            for (int i = 0; i < n && out_len < max_len; i++) {
                out[out_len++] = (uint8_t)('0' + (esp_random() % 10));
            }
        } else if (strncmp(tag, "rc ", 3) == 0) {
            int n = atoi(tag + 3);
            for (int i = 0; i < n && out_len < max_len; i++) {
                out[out_len++] = (uint8_t)alnum[esp_random() % (sizeof(alnum) - 1)];
            }
        } else if (strncmp(tag, "r ", 2) == 0) {
            int n = atoi(tag + 2);
            if (n > 0 && out_len + (size_t)n <= max_len) {
                esp_fill_random(out + out_len, n);
                out_len += n;
            }
        } else if (tag[0] == 't') {
            if (out_len + 4 <= max_len) {
                uint32_t ts = (uint32_t)time(NULL);
                awg_write_u32_le(out + out_len, ts);
                out_len += 4;
            }
        } else if (tag[0] == 'c') {
            if (out_len + 4 <= max_len) {
                awg_write_u32_le(out + out_len, ++awg_pkt_counter);
                out_len += 4;
            }
        }
        p = gt + 1;
    }
    return out_len;
}

/* Отправка пакета I1 и мусорных пакетов Jc перед каждым Handshake Initiation */
void awg_send_pre_handshake(struct udp_pcb *pcb, const ip_addr_t *ip, uint16_t port) {
    if (!pcb || !ip) return;

    if (orig_default_netif) {
        udp_bind_netif(pcb, orig_default_netif);
    }

    if (g_awg_cfg.i1[0] != '\0') {
        uint8_t *i1_buf = malloc(1200);
        if (i1_buf) {
            size_t i1_len = awg_build_i1_packet(i1_buf, 1200);
            if (i1_len > 0) {
                struct pbuf *pb = pbuf_alloc(PBUF_TRANSPORT, i1_len, PBUF_RAM);
                if (pb) {
                    memcpy(pb->payload, i1_buf, i1_len);
                    udp_sendto(pcb, pb, ip, port);
                    pbuf_free(pb);
                }
            }
            free(i1_buf);
        }
    }

    for (uint16_t i = 0; i < g_awg_cfg.jc; i++) {
        uint16_t jmin = g_awg_cfg.jmin > 0 ? g_awg_cfg.jmin : 40;
        uint16_t jmax = g_awg_cfg.jmax >= jmin ? g_awg_cfg.jmax : jmin;
        uint16_t jlen = (uint16_t)awg_rand_range(jmin, jmax);
        struct pbuf *jpb = pbuf_alloc(PBUF_TRANSPORT, jlen, PBUF_RAM);
        if (jpb) {
            esp_fill_random(jpb->payload, jlen);
            udp_sendto(pcb, jpb, ip, port);
            pbuf_free(jpb);
        }
    }
}

/* --- Обработчики CLI-команд для управления с Flipper Zero --- */

static void parse_h_range(const char *val, uint32_t *min_out, uint32_t *max_out) {
    const char *dash = strchr(val, '-');
    if (dash) {
        *min_out = (uint32_t)strtoul(val, NULL, 10);
        *max_out = (uint32_t)strtoul(dash + 1, NULL, 10);
        if (*max_out < *min_out) *max_out = *min_out;
    } else {
        *min_out = *max_out = (uint32_t)strtoul(val, NULL, 10);
    }
}

static void ensure_sntp(void) {
    if (!sntp_started) {
        esp_sntp_setoperatingmode(SNTP_OPMODE_POLL);
        esp_sntp_setservername(0, "pool.ntp.org");
        esp_sntp_init();
        sntp_started = true;
    }
    time_t now = 0;
    for (int i = 0; i < 20; i++) {
        time(&now);
        if (now > 1700000000) break;
        vTaskDelay(pdMS_TO_TICKS(200));
    }
}

/* Команда: awg_param <key> <value> */
static int cmd_awg_param(int argc, char **argv) {
    if (argc < 3) {
        printf("Usage: awg_param <key> <value>\n");
        return 1;
    }
    const char *k = argv[1];
    const char *v = argv[2];

    if (strcmp(k, "privkey") == 0) strncpy(g_awg_cfg.privkey, v, sizeof(g_awg_cfg.privkey) - 1);
    else if (strcmp(k, "pubkey") == 0) strncpy(g_awg_cfg.pubkey, v, sizeof(g_awg_cfg.pubkey) - 1);
    else if (strcmp(k, "psk") == 0) strncpy(g_awg_cfg.psk, v, sizeof(g_awg_cfg.psk) - 1);
    else if (strcmp(k, "ip") == 0) {
        strncpy(g_awg_cfg.ip, v, sizeof(g_awg_cfg.ip) - 1);
        char *slash = strchr(g_awg_cfg.ip, '/');
        if (slash) *slash = '\0';
    }
    else if (strcmp(k, "endpoint") == 0) strncpy(g_awg_cfg.endpoint, v, sizeof(g_awg_cfg.endpoint) - 1);
    else if (strcmp(k, "port") == 0) g_awg_cfg.port = atoi(v);
    else if (strcmp(k, "jc") == 0) g_awg_cfg.jc = (uint16_t)atoi(v);
    else if (strcmp(k, "jmin") == 0) g_awg_cfg.jmin = (uint16_t)atoi(v);
    else if (strcmp(k, "jmax") == 0) g_awg_cfg.jmax = (uint16_t)atoi(v);
    else if (strcmp(k, "s1") == 0) g_awg_cfg.s1 = (uint16_t)atoi(v);
    else if (strcmp(k, "s2") == 0) g_awg_cfg.s2 = (uint16_t)atoi(v);
    else if (strcmp(k, "s3") == 0) g_awg_cfg.s3 = (uint16_t)atoi(v);
    else if (strcmp(k, "s4") == 0) g_awg_cfg.s4 = (uint16_t)atoi(v);
    else if (strcmp(k, "h1") == 0) parse_h_range(v, &g_awg_cfg.h1_min, &g_awg_cfg.h1_max);
    else if (strcmp(k, "h2") == 0) parse_h_range(v, &g_awg_cfg.h2_min, &g_awg_cfg.h2_max);
    else if (strcmp(k, "h3") == 0) parse_h_range(v, &g_awg_cfg.h3_min, &g_awg_cfg.h3_max);
    else if (strcmp(k, "h4") == 0) parse_h_range(v, &g_awg_cfg.h4_min, &g_awg_cfg.h4_max);
    else if (strcmp(k, "i1_clear") == 0) g_awg_cfg.i1[0] = '\0';

    printf("AWG_PARAM_OK: %s\n", k);
    return 0;
}

/* Команда: awg_i1_chunk <chunk> (приём длинного параметра I1 по частям) */
static int cmd_awg_i1_chunk(int argc, char **argv) {
    if (argc < 2) return 1;
    size_t cur_len = strlen(g_awg_cfg.i1);

    for (int a = 1; a < argc; a++) {
        if (a > 1 && cur_len + 1 < sizeof(g_awg_cfg.i1) - 1) {
            g_awg_cfg.i1[cur_len++] = ' ';
            g_awg_cfg.i1[cur_len] = '\0';
        }
        const char *src = argv[a];
        while (*src && cur_len < sizeof(g_awg_cfg.i1) - 1) {
            g_awg_cfg.i1[cur_len++] = (*src == '~') ? ' ' : *src;
            src++;
        }
        g_awg_cfg.i1[cur_len] = '\0';
    }
    printf("AWG_I1_LEN: %u\n", (unsigned)cur_len);
    return 0;
}

/* Команда: awg_up (запуск туннеля и переключение маршрута NAT) */
static int cmd_awg_up(int argc, char **argv) {
    if (wg_active) {
        printf("AWG_STATUS: ALREADY_RUNNING\n");
        return 0;
    }

    if (netif_default != NULL) {
        orig_default_netif = netif_default;
    }

    ensure_sntp();

    wireguard_config_t wg_config = ESP_WIREGUARD_CONFIG_DEFAULT();
    wg_config.private_key = g_awg_cfg.privkey;
    wg_config.public_key = g_awg_cfg.pubkey;
    if (g_awg_cfg.psk[0] != '\0') {
        wg_config.preshared_key = g_awg_cfg.psk;
    }
    wg_config.allowed_ip = g_awg_cfg.ip;
    wg_config.allowed_ip_mask = "255.255.255.0";
    wg_config.endpoint = g_awg_cfg.endpoint;
    wg_config.port = g_awg_cfg.port;
    wg_config.persistent_keepalive = 25;

    if (esp_wireguard_init(&wg_config, &wg_ctx) != ESP_OK) {
        printf("AWG_ERROR: INIT_FAILED\n");
        return 1;
    }

    if (esp_wireguard_connect(&wg_ctx) != ESP_OK) {
        printf("AWG_ERROR: CONNECT_FAILED\n");
        return 1;
    }

    struct netif *wg_netif = wg_ctx.netif;
    if (!wg_netif) {
        struct netif *n;
        NETIF_FOREACH(n) {
            if (n->name[0] == 'w' && n->name[1] == 'g') {
                wg_netif = n;
                break;
            }
        }
    }

    if (wg_netif) {
        wg_netif->mtu = 1360;
        netif_set_default(wg_netif);
        ip_napt_enable(wg_netif->ip_addr.u_addr.ip4.addr, 1);
        ESP_LOGI(TAG, "NAPT and default route switched to AWG interface");
    }

    ip_addr_t dns_srv;
    IP_ADDR4(&dns_srv, 1, 1, 1, 1);
    dns_setserver(0, &dns_srv);

    wg_active = true;
    printf("AWG_STATUS: CONNECTED\n");
    return 0;
}

/* Команда: awg_down (остановка туннеля и возврат к прямому репитеру) */
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

/* Команда: awg_wipe (очистка ключей и конфига из RAM платы) */
static int cmd_awg_wipe(int argc, char **argv) {
    if (wg_active) {
        cmd_awg_down(0, NULL);
    }
    mbedtls_platform_zeroize(&g_awg_cfg, sizeof(g_awg_cfg));
    g_awg_cfg.port = 51820;
    g_awg_cfg.h1_min = g_awg_cfg.h1_max = 1;
    g_awg_cfg.h2_min = g_awg_cfg.h2_max = 2;
    g_awg_cfg.h3_min = g_awg_cfg.h3_max = 3;
    g_awg_cfg.h4_min = g_awg_cfg.h4_max = 4;
    printf("AWG_STATUS: RAM_WIPED\n");
    return 0;
}

/* Команда: awg_status (проверка состояния рукопожатия с сервером) */
static int cmd_awg_status(int argc, char **argv) {
    if (!wg_active) {
        printf("AWG_STATE: STOPPED (I1_LEN=%u)\n", (unsigned)strlen(g_awg_cfg.i1));
        return 0;
    }
    esp_err_t up = esp_wireguardif_peer_is_up(&wg_ctx);
    printf("AWG_STATE: %s (Endpoint=%s:%d, S3=%u, S4=%u, I1_LEN=%u)\n",
           (up == ESP_OK) ? "HANDSHAKE_OK" : "WAITING_HANDSHAKE",
           g_awg_cfg.endpoint, g_awg_cfg.port,
           g_awg_cfg.s3, g_awg_cfg.s4, (unsigned)strlen(g_awg_cfg.i1));
    return 0;
}

void register_awg_commands(void) {
    const esp_console_cmd_t cmds[] = {
        { .command = "awg_param",    .help = "Set AWG param in RAM",         .func = &cmd_awg_param },
        { .command = "awg_i1_chunk", .help = "Append I1 CPS signature",      .func = &cmd_awg_i1_chunk },
        { .command = "awg_up",       .help = "Start AWG 2.0 VPN tunnel",     .func = &cmd_awg_up },
        { .command = "awg_down",     .help = "Stop AWG 2.0 VPN tunnel",      .func = &cmd_awg_down },
        { .command = "awg_wipe",     .help = "Wipe AWG config from RAM",     .func = &cmd_awg_wipe },
        { .command = "awg_status",   .help = "Check AWG handshake status",   .func = &cmd_awg_status }
    };
    for (size_t i = 0; i < sizeof(cmds) / sizeof(cmds[0]); i++) {
        esp_console_cmd_register(&cmds[i]);
    }
}
