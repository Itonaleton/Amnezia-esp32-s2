#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include <sys/time.h>
#include "esp_log.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "driver/gpio.h"
#include "esp_console.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_sntp.h"
#include "esp_random.h"
#include "esp_wireguard.h"
#include "lwip/netif.h"
#include "lwip/udp.h"
#include "lwip/dns.h"
#include "lwip/lwip_napt.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "mbedtls/platform_util.h"

static const char *TAG = "awg_ctrl";

typedef struct {
    char privkey[64];
    char pubkey[64];
    char psk[64];
    char ip[32];
    char endpoint[96];
    int  port;
    uint16_t jc, jmin, jmax;
    uint16_t s1, s2, s3, s4;
    uint32_t h1_min, h1_max;
    uint32_t h2_min, h2_max;
    uint32_t h3_min, h3_max;
    uint32_t h4_min, h4_max;
    uint8_t  hpk[32];
    bool     hpk_set;
    char     i1[1024];
} awg_runtime_params_t;

awg_runtime_params_t g_awg_cfg = {
    .port = 51820,
    .jc = 4, .jmin = 40, .jmax = 70,
    .s1 = 0, .s2 = 0, .s3 = 0, .s4 = 0,
    .h1_min = 1, .h1_max = 1,
    .h2_min = 2, .h2_max = 2,
    .h3_min = 3, .h3_max = 3,
    .h4_min = 4, .h4_max = 4,
    .hpk_set = false
};

static wireguard_config_t wg_config = ESP_WIREGUARD_CONFIG_DEFAULT();
static wireguard_ctx_t wg_ctx = {0};
static bool wg_inited = false;
static bool wg_active = false;
static volatile bool awg_wanted = false;   /* user asked for the tunnel (awg_up called) */
static struct netif *orig_default_netif = NULL;
static uint32_t awg_pkt_counter = 0;

/* --- Потоковый шифр ChaCha20 IETF (для HeaderProtectionKey) --- */

#define AWG_ROTL32(v, n) (((v) << (n)) | ((v) >> (32 - (n))))
#define AWG_QR(a, b, c, d) do { \
    a += b; d ^= a; d = AWG_ROTL32(d, 16); \
    c += d; b ^= c; b = AWG_ROTL32(b, 12); \
    a += b; d ^= a; d = AWG_ROTL32(d, 8);  \
    c += d; b ^= c; b = AWG_ROTL32(b, 7);  \
} while (0)

static uint32_t awg_read_u32_le(const uint8_t *p) {
    if (!p) return 0;
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void awg_write_u32_le(uint8_t *p, uint32_t v) {
    if (!p) return;
    p[0] = (uint8_t)(v & 0xFF);
    p[1] = (uint8_t)((v >> 8) & 0xFF);
    p[2] = (uint8_t)((v >> 16) & 0xFF);
    p[3] = (uint8_t)((v >> 24) & 0xFF);
}

static void awg_chacha20_xor(uint8_t *buf, size_t len, const uint8_t key[32], const uint8_t nonce[12]) {
    uint32_t state[16], x[16];
    uint8_t block[64];
    uint32_t counter = 0;

    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;
    for (int i = 0; i < 8; i++) {
        state[4 + i] = awg_read_u32_le(key + i * 4);
    }
    state[13] = awg_read_u32_le(nonce + 0);
    state[14] = awg_read_u32_le(nonce + 4);
    state[15] = awg_read_u32_le(nonce + 8);

    size_t offset = 0;
    while (offset < len) {
        state[12] = counter++;
        for (int i = 0; i < 16; i++) x[i] = state[i];
        for (int i = 0; i < 10; i++) {
            AWG_QR(x[0], x[4], x[8],  x[12]);
            AWG_QR(x[1], x[5], x[9],  x[13]);
            AWG_QR(x[2], x[6], x[10], x[14]);
            AWG_QR(x[3], x[7], x[11], x[15]);
            AWG_QR(x[0], x[5], x[10], x[15]);
            AWG_QR(x[1], x[6], x[11], x[12]);
            AWG_QR(x[2], x[7], x[8],  x[13]);
            AWG_QR(x[3], x[4], x[9],  x[14]);
        }
        for (int i = 0; i < 16; i++) {
            awg_write_u32_le(block + i * 4, x[i] + state[i]);
        }
        size_t chunk = (len - offset > 64) ? 64 : (len - offset);
        for (size_t i = 0; i < chunk; i++) {
            buf[offset + i] ^= block[i];
        }
        offset += chunk;
    }
}

static bool awg_base64_decode_32(const char *in, uint8_t out[32]) {
    if (!in) return false;
    uint32_t val = 0;
    int valb = -8;
    size_t out_len = 0;
    for (const char *p = in; *p && *p != '='; p++) {
        int c = (unsigned char)*p;
        int d = -1;
        if (c >= 'A' && c <= 'Z') d = c - 'A';
        else if (c >= 'a' && c <= 'z') d = c - 'a' + 26;
        else if (c >= '0' && c <= '9') d = c - '0' + 52;
        else if (c == '+') d = 62;
        else if (c == '/') d = 63;
        if (d < 0) continue;
        val = (val << 6) + (uint32_t)d;
        valb += 6;
        if (valb >= 0) {
            if (out_len < 32) out[out_len++] = (uint8_t)((val >> valb) & 0xFF);
            valb -= 8;
        }
    }
    return (out_len == 32);
}

static uint32_t awg_rand_range(uint32_t min_v, uint32_t max_v) {
    if (max_v <= min_v) return min_v;
    return min_v + (esp_random() % (max_v - min_v + 1));
}

void awg_write_h1(uint8_t *p) { awg_write_u32_le(p, awg_rand_range(g_awg_cfg.h1_min, g_awg_cfg.h1_max)); }
void awg_write_h2(uint8_t *p) { awg_write_u32_le(p, awg_rand_range(g_awg_cfg.h2_min, g_awg_cfg.h2_max)); }
void awg_write_h3(uint8_t *p) { awg_write_u32_le(p, awg_rand_range(g_awg_cfg.h3_min, g_awg_cfg.h3_max)); }
void awg_write_h4(uint8_t *p) { awg_write_u32_le(p, awg_rand_range(g_awg_cfg.h4_min, g_awg_cfg.h4_max)); }

bool awg_check_h1(const uint8_t *p) { uint32_t v = awg_read_u32_le(p); return (v >= g_awg_cfg.h1_min && v <= g_awg_cfg.h1_max); }
bool awg_check_h2(const uint8_t *p) { uint32_t v = awg_read_u32_le(p); return (v >= g_awg_cfg.h2_min && v <= g_awg_cfg.h2_max); }
bool awg_check_h3(const uint8_t *p) { uint32_t v = awg_read_u32_le(p); return (v >= g_awg_cfg.h3_min && v <= g_awg_cfg.h3_max); }
bool awg_check_h4(const uint8_t *p) { uint32_t v = awg_read_u32_le(p); return (v >= g_awg_cfg.h4_min && v <= g_awg_cfg.h4_max); }

uint16_t awg_get_tx_prefix_len(const uint8_t *data, size_t len) {
    if (!data || len < 4) return 0;
    if (len == 148 && awg_check_h1(data)) return g_awg_cfg.s1;
    if (len == 92  && awg_check_h2(data)) return g_awg_cfg.s2;
    if (len == 64  && awg_check_h3(data)) return g_awg_cfg.s3;
    if (len >= 32  && awg_check_h4(data)) return g_awg_cfg.s4;
    return 0;
}

void awg_apply_tx_header_protection(uint8_t *full_pkt, uint16_t s_len, size_t wg_len) {
    if (!full_pkt || !g_awg_cfg.hpk_set || s_len < 12) return;
    uint8_t *wg_hdr = full_pkt + s_len;
    /* Decide by message TYPE as well as length: a transport packet can be 64/92/148 bytes long too. */
    if (wg_len == 148 && awg_check_h1(wg_hdr)) {
        awg_chacha20_xor(wg_hdr, wg_len, g_awg_cfg.hpk, full_pkt);
    } else if (wg_len == 92 && awg_check_h2(wg_hdr)) {
        awg_chacha20_xor(wg_hdr, wg_len, g_awg_cfg.hpk, full_pkt);
    } else if (wg_len == 64 && awg_check_h3(wg_hdr)) {
        awg_chacha20_xor(wg_hdr, wg_len, g_awg_cfg.hpk, full_pkt);
    } else if (wg_len >= 32 && awg_check_h4(wg_hdr)) {
        awg_chacha20_xor(wg_hdr, 16, g_awg_cfg.hpk, full_pkt);
    }
}

/* Безопасное снятие префикса S1..S4 через memmove (сохраняет 4-байтное выравнивание на ESP32-S2) */
void awg_strip_rx_prefix(uint8_t **data, size_t *len) {
    if (!data || !*data || !len) return;
    uint8_t *d = *data;
    size_t l = *len;

    if (g_awg_cfg.hpk_set && l >= 16) {
        uint8_t ks_probe[4] = {0, 0, 0, 0};
        awg_chacha20_xor(ks_probe, 4, g_awg_cfg.hpk, d);
        uint32_t mask = awg_read_u32_le(ks_probe);

        if (g_awg_cfg.s1 >= 12 && l >= (size_t)(g_awg_cfg.s1 + 148)) {
            uint32_t h = awg_read_u32_le(d + g_awg_cfg.s1) ^ mask;
            if (h >= g_awg_cfg.h1_min && h <= g_awg_cfg.h1_max) {
                awg_chacha20_xor(d + g_awg_cfg.s1, 148, g_awg_cfg.hpk, d);
                memmove(d, d + g_awg_cfg.s1, 148);
                *len = 148;
                return;
            }
        }
        if (g_awg_cfg.s2 >= 12 && l >= (size_t)(g_awg_cfg.s2 + 92)) {
            uint32_t h = awg_read_u32_le(d + g_awg_cfg.s2) ^ mask;
            if (h >= g_awg_cfg.h2_min && h <= g_awg_cfg.h2_max) {
                awg_chacha20_xor(d + g_awg_cfg.s2, 92, g_awg_cfg.hpk, d);
                memmove(d, d + g_awg_cfg.s2, 92);
                *len = 92;
                return;
            }
        }
        if (g_awg_cfg.s3 >= 12 && l >= (size_t)(g_awg_cfg.s3 + 64)) {
            uint32_t h = awg_read_u32_le(d + g_awg_cfg.s3) ^ mask;
            if (h >= g_awg_cfg.h3_min && h <= g_awg_cfg.h3_max) {
                awg_chacha20_xor(d + g_awg_cfg.s3, 64, g_awg_cfg.hpk, d);
                memmove(d, d + g_awg_cfg.s3, 64);
                *len = 64;
                return;
            }
        }
        if (g_awg_cfg.s4 >= 12 && l >= (size_t)(g_awg_cfg.s4 + 32)) {
            uint32_t h = awg_read_u32_le(d + g_awg_cfg.s4) ^ mask;
            if (h >= g_awg_cfg.h4_min && h <= g_awg_cfg.h4_max) {
                awg_chacha20_xor(d + g_awg_cfg.s4, 16, g_awg_cfg.hpk, d);
                size_t new_len = l - g_awg_cfg.s4;
                memmove(d, d + g_awg_cfg.s4, new_len);
                *len = new_len;
                return;
            }
        }
        return;
    }

    if (l == (size_t)(g_awg_cfg.s1 + 148) && awg_check_h1(d + g_awg_cfg.s1)) {
        if (g_awg_cfg.s1 > 0) memmove(d, d + g_awg_cfg.s1, 148);
        *len = 148;
    } else if (l == (size_t)(g_awg_cfg.s2 + 92) && awg_check_h2(d + g_awg_cfg.s2)) {
        if (g_awg_cfg.s2 > 0) memmove(d, d + g_awg_cfg.s2, 92);
        *len = 92;
    } else if (l == (size_t)(g_awg_cfg.s3 + 64) && awg_check_h3(d + g_awg_cfg.s3)) {
        if (g_awg_cfg.s3 > 0) memmove(d, d + g_awg_cfg.s3, 64);
        *len = 64;
    } else if (l >= (size_t)(g_awg_cfg.s4 + 32) && awg_check_h4(d + g_awg_cfg.s4)) {
        size_t new_len = l - g_awg_cfg.s4;
        if (g_awg_cfg.s4 > 0) memmove(d, d + g_awg_cfg.s4, new_len);
        *len = new_len;
    }
}

static int hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

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
                } else break;
            }
        } else if (strncmp(tag, "rd ", 3) == 0) {
            int n = atoi(tag + 3);
            for (int i = 0; i < n && out_len < max_len; i++)
                out[out_len++] = (uint8_t)('0' + (esp_random() % 10));
        } else if (strncmp(tag, "rc ", 3) == 0) {
            int n = atoi(tag + 3);
            for (int i = 0; i < n && out_len < max_len; i++)
                out[out_len++] = (uint8_t)alnum[esp_random() % (sizeof(alnum) - 1)];
        } else if (strncmp(tag, "r ", 2) == 0) {
            int n = atoi(tag + 2);
            if (n > 0 && out_len + (size_t)n <= max_len) {
                esp_fill_random(out + out_len, n);
                out_len += n;
            }
        } else if (tag[0] == 't') {
            if (out_len + 4 <= max_len) {
                uint32_t ts = (uint32_t)time(NULL);
                out[out_len++] = (uint8_t)((ts >> 24) & 0xFF);
                out[out_len++] = (uint8_t)((ts >> 16) & 0xFF);
                out[out_len++] = (uint8_t)((ts >> 8) & 0xFF);
                out[out_len++] = (uint8_t)(ts & 0xFF);
            }
        } else if (tag[0] == 'c') {
            if (out_len + 4 <= max_len) {
                uint32_t cnt = ++awg_pkt_counter;
                out[out_len++] = (uint8_t)((cnt >> 24) & 0xFF);
                out[out_len++] = (uint8_t)((cnt >> 16) & 0xFF);
                out[out_len++] = (uint8_t)((cnt >> 8) & 0xFF);
                out[out_len++] = (uint8_t)(cnt & 0xFF);
            }
        }
        p = gt + 1;
    }
    return out_len;
}

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
        if (jmax > 1200) jmax = 1200;
        uint16_t jlen = (uint16_t)awg_rand_range(jmin, jmax);
        struct pbuf *jpb = pbuf_alloc(PBUF_TRANSPORT, jlen, PBUF_RAM);
        if (jpb) {
            esp_fill_random(jpb->payload, jlen);
            udp_sendto(pcb, jpb, ip, port);
            pbuf_free(jpb);
        }
    }
}

/* Traffic counters (updated from the patched esp_wireguard, shown by awg_status) */
volatile uint32_t g_awg_tx_ok = 0;
volatile uint32_t g_awg_tx_fail = 0;
volatile uint32_t g_awg_rx_pkts = 0;
volatile uint32_t g_awg_tx_bytes = 0;
volatile uint32_t g_awg_rx_bytes = 0;

/* TCP MSS clamping: rewrite the MSS option of IPv4 TCP SYN/SYN-ACK packets so that
 * segments fit into the tunnel MTU (prevents the classic "small pages load, big ones hang"
 * problem). TCP checksum is updated incrementally (RFC 1624). */
void awg_clamp_mss(struct pbuf *q, uint16_t max_mss) {
    if (!q || !q->payload || q->len < 40) return;
    uint8_t *ip = (uint8_t *)q->payload;
    if ((ip[0] >> 4) != 4 || ip[9] != 6) return;           /* IPv4 + TCP only */
    uint16_t ihl = (uint16_t)((ip[0] & 0x0f) * 4);
    if (ihl < 20 || q->len < (uint16_t)(ihl + 20)) return;
    uint8_t *tcp = ip + ihl;
    if (!(tcp[13] & 0x02)) return;                          /* SYN flag */
    uint16_t doff = (uint16_t)((tcp[12] >> 4) * 4);
    if (doff < 24 || q->len < (uint16_t)(ihl + doff)) return;
    uint8_t *opt = tcp + 20;
    uint8_t *end = tcp + doff;
    while (opt < end) {
        uint8_t kind = opt[0];
        if (kind == 0) break;
        if (kind == 1) { opt++; continue; }
        if (opt + 1 >= end) break;
        uint8_t olen = opt[1];
        if (olen < 2 || opt + olen > end) break;
        if (kind == 2 && olen == 4) {
            uint16_t mss = (uint16_t)((opt[2] << 8) | opt[3]);
            if (mss > max_mss) {
                uint32_t sum = (uint16_t)~(uint16_t)((tcp[16] << 8) | tcp[17]);
                sum += (uint16_t)~mss;
                sum += max_mss;
                while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
                uint16_t csum = (uint16_t)~sum;
                opt[2] = (uint8_t)(max_mss >> 8);
                opt[3] = (uint8_t)(max_mss & 0xff);
                tcp[16] = (uint8_t)(csum >> 8);
                tcp[17] = (uint8_t)(csum & 0xff);
            }
            break;
        }
        opt += olen;
    }
}

/* --- CLI-команды --- */

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

static bool ensure_time(void) {
    const time_t valid_after = 1700000000;
    if (time(NULL) > valid_after) return true;

    ip_addr_t dns_fallback;
    IP_ADDR4(&dns_fallback, 1, 1, 1, 1);
    dns_setserver(1, &dns_fallback);

    if (esp_sntp_enabled()) {
        esp_sntp_stop();
    }
    esp_sntp_setoperatingmode(ESP_SNTP_OPMODE_POLL);
    esp_sntp_setservername(0, "pool.ntp.org");
    esp_sntp_init();

    for (int i = 0; i < 40; i++) {
        if (time(NULL) > valid_after) return true;
        vTaskDelay(pdMS_TO_TICKS(200));
    }

    struct timeval tv = { .tv_sec = 1793750000 + (esp_random() % 60000), .tv_usec = 0 };
    settimeofday(&tv, NULL);
    return true;
}

static int cmd_awg_param(int argc, char **argv) {
    if (argc < 3) {
        printf("AWG_ERROR: BAD_ARGS\n");
        fflush(stdout);
        return 1;
    }
    const char *k = argv[1];
    const char *v = argv[2];

    if (strcmp(k, "privkey") == 0) strncpy(g_awg_cfg.privkey, v, sizeof(g_awg_cfg.privkey) - 1);
    else if (strcmp(k, "pubkey") == 0) strncpy(g_awg_cfg.pubkey, v, sizeof(g_awg_cfg.pubkey) - 1);
    else if (strcmp(k, "psk") == 0) strncpy(g_awg_cfg.psk, v, sizeof(g_awg_cfg.psk) - 1);
    else if (strcmp(k, "hpk") == 0) {
        g_awg_cfg.hpk_set = awg_base64_decode_32(v, g_awg_cfg.hpk);
    }
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
    fflush(stdout);
    return 0;
}

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
    fflush(stdout);
    return 0;
}

static int cmd_awg_i1(int argc, char **argv) {
    if (argc >= 2 && strcmp(argv[1], "clear") == 0) {
        g_awg_cfg.i1[0] = '\0';
        printf("AWG_I1_OK: cleared\n");
        fflush(stdout);
        return 0;
    }
    if (argc >= 3 && strcmp(argv[1], "add") == 0) {
        size_t cur_len = strlen(g_awg_cfg.i1);
        size_t add_len = strlen(argv[2]);
        if (cur_len + add_len >= sizeof(g_awg_cfg.i1) - 1) {
            printf("AWG_ERROR: I1_TOO_LONG\n");
            fflush(stdout);
            return 1;
        }
        strcat(g_awg_cfg.i1, argv[2]);
        printf("AWG_I1_OK: %u\n", (unsigned)strlen(g_awg_cfg.i1));
        fflush(stdout);
        return 0;
    }
    printf("AWG_ERROR: BAD_I1_CMD\n");
    fflush(stdout);
    return 1;
}

static int cmd_awg_up(int argc, char **argv) {
    awg_wanted = true;
    if (wg_active) {
        printf("AWG_STATUS: ALREADY_RUNNING\n");
        fflush(stdout);
        return 0;
    }
    if (!g_awg_cfg.privkey[0] || !g_awg_cfg.pubkey[0] || !g_awg_cfg.ip[0] || !g_awg_cfg.endpoint[0]) {
        printf("AWG_ERROR: MISSING_PARAMS\n");
        fflush(stdout);
        return 1;
    }

    if (orig_default_netif == NULL && netif_default != NULL) {
        orig_default_netif = netif_default;
    }

    printf("AWG_CFG: jc=%u jmin=%u jmax=%u s1=%u s2=%u s3=%u s4=%u "
           "h1=%u-%u h2=%u-%u h3=%u-%u h4=%u-%u hpk=%d i1_len=%u port=%d ep=%s\n",
           (unsigned)g_awg_cfg.jc, (unsigned)g_awg_cfg.jmin, (unsigned)g_awg_cfg.jmax,
           (unsigned)g_awg_cfg.s1, (unsigned)g_awg_cfg.s2, (unsigned)g_awg_cfg.s3, (unsigned)g_awg_cfg.s4,
           (unsigned)g_awg_cfg.h1_min, (unsigned)g_awg_cfg.h1_max,
           (unsigned)g_awg_cfg.h2_min, (unsigned)g_awg_cfg.h2_max,
           (unsigned)g_awg_cfg.h3_min, (unsigned)g_awg_cfg.h3_max,
           (unsigned)g_awg_cfg.h4_min, (unsigned)g_awg_cfg.h4_max,
           g_awg_cfg.hpk_set ? 1 : 0, (unsigned)strlen(g_awg_cfg.i1),
           g_awg_cfg.port, g_awg_cfg.endpoint);
    fflush(stdout);
    printf("AWG_TIME: before_sync=%lld\n", (long long)time(NULL));
    fflush(stdout);
    ensure_time();
    printf("AWG_TIME: after_sync=%lld sntp_status=%d (0=reset 1=completed 2=in_progress)\n",
           (long long)time(NULL), (int)sntp_get_sync_status());
    fflush(stdout);

    if (!wg_inited) {
        wireguard_config_t tmp = ESP_WIREGUARD_CONFIG_DEFAULT();
        wg_config = tmp;
        wg_config.private_key = g_awg_cfg.privkey;
        wg_config.public_key = g_awg_cfg.pubkey;
        wg_config.preshared_key = g_awg_cfg.psk[0] ? g_awg_cfg.psk : NULL;
        wg_config.allowed_ip = g_awg_cfg.ip;
        wg_config.allowed_ip_mask = "255.255.255.0";
        wg_config.endpoint = g_awg_cfg.endpoint;
        wg_config.port = g_awg_cfg.port;
        wg_config.persistent_keepalive = 25;

        memset(&wg_ctx, 0, sizeof(wg_ctx));
        wg_ctx.netif_default = orig_default_netif;

        if (esp_wireguard_init(&wg_config, &wg_ctx) != ESP_OK) {
            printf("AWG_ERROR: INIT_FAILED\n");
            fflush(stdout);
            return 1;
        }
        if (esp_wireguard_connect(&wg_ctx) != ESP_OK) {
            printf("AWG_ERROR: CONNECT_FAILED\n");
            fflush(stdout);
            return 1;
        }
        wg_inited = true;
    }

    bool up = false;
    for (int i = 0; i < 90; i++) {
        if (esp_wireguardif_peer_is_up(&wg_ctx) == ESP_OK) {
            up = true;
            break;
        }
        vTaskDelay(pdMS_TO_TICKS(200));
    }

    if (!up) {
        printf("AWG_ERROR: HANDSHAKE_TIMEOUT (hpk=%d)\n", g_awg_cfg.hpk_set ? 1 : 0);
        fflush(stdout);
        return 1;
    }

    if (wg_ctx.netif) {
        wg_ctx.netif->mtu = 1280;
        netif_set_default(wg_ctx.netif);
        /* NAPT stays enabled on the AP (inside) netif only (done in main). Enabling it on the
           tunnel (outside) netif stops reverse translation of replies coming back from the server. */
        printf("AWG_NET: default=%c%c%u mtu=%u\n",
               wg_ctx.netif->name[0], wg_ctx.netif->name[1], (unsigned)wg_ctx.netif->num,
               (unsigned)wg_ctx.netif->mtu);
        fflush(stdout);
    }

    ip_addr_t dns_srv;
    IP_ADDR4(&dns_srv, 1, 1, 1, 1);
    dns_setserver(0, &dns_srv);

    wg_active = true;
    printf("AWG_STATUS: CONNECTED\n");
    fflush(stdout);
    return 0;
}

static int cmd_awg_down(int argc, char **argv) {
    awg_wanted = false;
    if (orig_default_netif != NULL) {
        netif_set_default(orig_default_netif);
    }
    wg_active = false;
    printf("AWG_STATUS: DISCONNECTED\n");
    fflush(stdout);
    return 0;
}

static int cmd_awg_wipe(int argc, char **argv) {
    awg_wanted = false;
    if (orig_default_netif != NULL) {
        netif_set_default(orig_default_netif);
    }
    wg_active = false;
    mbedtls_platform_zeroize(&g_awg_cfg, sizeof(g_awg_cfg));
    g_awg_cfg.port = 51820;
    g_awg_cfg.h1_min = g_awg_cfg.h1_max = 1;
    g_awg_cfg.h2_min = g_awg_cfg.h2_max = 2;
    g_awg_cfg.h3_min = g_awg_cfg.h3_max = 3;
    g_awg_cfg.h4_min = g_awg_cfg.h4_max = 4;
    printf("AWG_STATUS: RAM_WIPED\n");
    fflush(stdout);
    return 0;
}

/* Live speed: call repeatedly; each call reports the rate since the previous call.
 * Output uses '|' as a line separator so the Flipper app can show it on several lines. */
static int cmd_awg_speed(int argc, char **argv) {
    static int64_t last_us = 0;
    static uint32_t last_txp = 0, last_txb = 0, last_rxp = 0, last_rxb = 0, last_fail = 0;

    int64_t now = esp_timer_get_time();
    uint32_t txp = g_awg_tx_ok, txb = g_awg_tx_bytes, rxp = g_awg_rx_pkts, rxb = g_awg_rx_bytes;
    uint32_t fail = g_awg_tx_fail;

    if (last_us == 0) {
        last_us = now; last_txp = txp; last_txb = txb; last_rxp = rxp; last_rxb = rxb; last_fail = fail;
        printf("AWG_SPEED: baseline set\n");
        fflush(stdout);
        return 0;
    }

    uint32_t dt_ms = (uint32_t)((now - last_us) / 1000);
    if (dt_ms == 0) dt_ms = 1;

    uint32_t tx_pps = (uint32_t)(((uint64_t)(txp - last_txp) * 1000ULL) / dt_ms);
    uint32_t rx_pps = (uint32_t)(((uint64_t)(rxp - last_rxp) * 1000ULL) / dt_ms);
    /* KB/s * 10 (one decimal), KB = 1024 bytes */
    uint32_t tx_k10 = (uint32_t)(((uint64_t)(txb - last_txb) * 10000ULL) / (1024ULL * dt_ms));
    uint32_t rx_k10 = (uint32_t)(((uint64_t)(rxb - last_rxb) * 10000ULL) / (1024ULL * dt_ms));

    printf("AWG_SPEED: TX %u pkt/s  %u.%u KB/s|RX %u pkt/s  %u.%u KB/s|tx_fail +%u  dt %u ms\n",
           (unsigned)tx_pps, (unsigned)(tx_k10 / 10), (unsigned)(tx_k10 % 10),
           (unsigned)rx_pps, (unsigned)(rx_k10 / 10), (unsigned)(rx_k10 % 10),
           (unsigned)(fail - last_fail), (unsigned)dt_ms);
    fflush(stdout);

    last_us = now; last_txp = txp; last_txb = txb; last_rxp = rxp; last_rxb = rxb; last_fail = fail;
    return 0;
}

static int cmd_awg_status(int argc, char **argv) {
    bool up = wg_inited && (esp_wireguardif_peer_is_up(&wg_ctx) == ESP_OK);
    printf("AWG_STATUS: %s peer_up=%d time_ok=%d hpk=%d i1_len=%u\n",
           wg_active ? "ACTIVE" : "STOPPED",
           up ? 1 : 0,
           (time(NULL) > 1700000000) ? 1 : 0,
           g_awg_cfg.hpk_set ? 1 : 0,
           (unsigned)strlen(g_awg_cfg.i1));
    printf("AWG_STATS: tx_ok=%u tx_fail=%u rx=%u heap=%u min_heap=%u\n",
           (unsigned)g_awg_tx_ok, (unsigned)g_awg_tx_fail, (unsigned)g_awg_rx_pkts,
           (unsigned)esp_get_free_heap_size(), (unsigned)esp_get_minimum_free_heap_size());
    fflush(stdout);
    return 0;
}

/* ------------------------------------------------------------------------------------
 * LED indication
 *   everything fine : one short blink every 30 s ("heartbeat")
 *   something wrong : a group of quick blinks, repeated every 3 s while the problem lasts
 *        2 blinks -> no connection to the upstream Wi-Fi (STA)
 *        3 blinks -> tunnel was requested (awg_up) but is not up / lost the server
 *        4 blinks -> low free memory
 * A problem must last 8 s before it is shown (avoids flicker during re-connects).
 * Change AWG_LED_GPIO (or define it in build flags) if your LED is on another pin.
 * ------------------------------------------------------------------------------------ */
#ifndef AWG_LED_GPIO
#define AWG_LED_GPIO 2            /* same pin as the stock firmware */
#endif
#ifndef AWG_LED_ACTIVE_LOW
#define AWG_LED_ACTIVE_LOW 0      /* set to 1 if the LED lights when the pin is LOW */
#endif
#define AWG_LED_HEARTBEAT_MS        30000
#define AWG_LED_PROBLEM_REPEAT_MS    3000
#define AWG_LED_PROBLEM_DEBOUNCE_MS  8000
#define AWG_LED_LOW_HEAP_BYTES      16000

extern bool ap_connect;           /* main: STA connected and has an IP */
extern char *ssid;                /* main: configured upstream SSID ("" = AP-only mode) */

static void awg_led_set(bool on) {
    gpio_set_level(AWG_LED_GPIO, ((on ? 1 : 0) ^ AWG_LED_ACTIVE_LOW) ? 1 : 0);
}

static void awg_led_blink(int times, int on_ms, int off_ms) {
    for (int i = 0; i < times; i++) {
        awg_led_set(true);
        vTaskDelay(pdMS_TO_TICKS(on_ms));
        awg_led_set(false);
        if (off_ms > 0) vTaskDelay(pdMS_TO_TICKS(off_ms));
    }
}

/* 0 = fine, otherwise the number of blinks that signals the problem */
static int awg_led_problem(void) {
    bool sta_expected = (ssid != NULL && ssid[0] != '\0');
    if (sta_expected && !ap_connect) return 2;
    if (awg_wanted) {
        bool up = wg_inited && wg_active && (esp_wireguardif_peer_is_up(&wg_ctx) == ESP_OK);
        if (!up) return 3;
    }
    if (esp_get_free_heap_size() < AWG_LED_LOW_HEAP_BYTES) return 4;
    return 0;
}

void awg_led_task(void *arg) {
    gpio_reset_pin(AWG_LED_GPIO);
    gpio_set_direction(AWG_LED_GPIO, GPIO_MODE_OUTPUT);
    awg_led_set(false);

    int64_t now = esp_timer_get_time() / 1000;
    int64_t last_heartbeat = now - AWG_LED_HEARTBEAT_MS + 5000;   /* first heartbeat 5 s after start */
    int64_t last_problem_show = 0;
    int64_t bad_since = 0;
    int bad_kind = 0;

    for (;;) {
        now = esp_timer_get_time() / 1000;
        int p = awg_led_problem();
        if (p == 0) {
            bad_kind = 0;
            bad_since = 0;
        } else if (p != bad_kind) {
            bad_kind = p;
            bad_since = now;
        }

        if (bad_kind != 0) {
            if (now - bad_since >= AWG_LED_PROBLEM_DEBOUNCE_MS &&
                now - last_problem_show >= AWG_LED_PROBLEM_REPEAT_MS) {
                awg_led_blink(bad_kind, 120, 180);
                last_problem_show = now;
            }
        } else if (now - last_heartbeat >= AWG_LED_HEARTBEAT_MS) {
            awg_led_blink(1, 150, 0);
            last_heartbeat = now;
        }
        vTaskDelay(pdMS_TO_TICKS(250));
    }
}

void register_awg_commands(void) {
    const esp_console_cmd_t cmds[] = {
        { .command = "awg_param",    .help = "Set AmneziaWG parameter (RAM only)", .func = &cmd_awg_param },
        { .command = "awg_i1",       .help = "awg_i1 clear | add \"<chunk>\"",      .func = &cmd_awg_i1 },
        { .command = "awg_i1_chunk", .help = "Append I1 CPS signature",            .func = &cmd_awg_i1_chunk },
        { .command = "awg_up",       .help = "Start AmneziaWG tunnel",             .func = &cmd_awg_up },
        { .command = "awg_down",     .help = "Stop tunnel, restore direct route",  .func = &cmd_awg_down },
        { .command = "awg_wipe",     .help = "Stop tunnel and wipe RAM config",    .func = &cmd_awg_wipe },
        { .command = "awg_status",   .help = "Show tunnel status",                 .func = &cmd_awg_status },
        { .command = "awg_speed",    .help = "Show tunnel speed since last call", .func = &cmd_awg_speed },
    };
    for (size_t i = 0; i < sizeof(cmds) / sizeof(cmds[0]); i++) {
        ESP_ERROR_CHECK(esp_console_cmd_register(&cmds[i]));
    }
    ESP_LOGI(TAG, "AmneziaWG commands registered");
}
