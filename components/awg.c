#include "awg.h"
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>
#include <esp_random.h>
#include <mbedtls/platform_util.h>

#define AWG_I1_MAX_STR 2048

awg_params_t g_awg = {0};

static uint32_t awg_counter = 0;

static int parse_u32(const char *v, uint32_t *out)
{
    char *end = NULL;
    if (!v || !*v) return -1;
    unsigned long x = strtoul(v, &end, 10);
    if (*end != '\0') return -1;
    *out = (uint32_t)x;
    return 0;
}

void awg_i1_clear(void)
{
    if (g_awg.i1) {
        mbedtls_platform_zeroize(g_awg.i1, strlen(g_awg.i1));
        free(g_awg.i1);
        g_awg.i1 = NULL;
    }
}

int awg_i1_append(const char *chunk)
{
    size_t old = g_awg.i1 ? strlen(g_awg.i1) : 0;
    size_t add = strlen(chunk);
    if (old + add >= AWG_I1_MAX_STR) return -1;
    char *n = realloc(g_awg.i1, old + add + 1);
    if (!n) return -1;
    memcpy(n + old, chunk, add + 1);
    g_awg.i1 = n;
    return 0;
}

int awg_set_param(const char *key, const char *value)
{
    uint32_t v;
    if (parse_u32(value, &v) != 0) return -1;
    if (!strcasecmp(key, "jc"))        g_awg.jc = v;
    else if (!strcasecmp(key, "jmin")) g_awg.jmin = v;
    else if (!strcasecmp(key, "jmax")) g_awg.jmax = v;
    else if (!strcasecmp(key, "s1"))   g_awg.s1 = v;
    else if (!strcasecmp(key, "s2"))   g_awg.s2 = v;
    else if (!strcasecmp(key, "s3"))   g_awg.s3 = v;
    else if (!strcasecmp(key, "s4"))   g_awg.s4 = v;
    /* only the static headers 1..4 are supported */
    else if (!strcasecmp(key, "h1"))   return v == 1 ? 0 : -1;
    else if (!strcasecmp(key, "h2"))   return v == 2 ? 0 : -1;
    else if (!strcasecmp(key, "h3"))   return v == 3 ? 0 : -1;
    else if (!strcasecmp(key, "h4"))   return v == 4 ? 0 : -1;
    else return -1;
    return 0;
}

void awg_wipe(void)
{
    awg_i1_clear();
    memset(&g_awg, 0, sizeof(g_awg));
}

/* ---- I1 template parser: <b 0xHEX> <r N> <rc N> <rd N> <t> <c> ---- */

static int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

size_t awg_build_i1(uint8_t *out, size_t max)
{
    const char *p = g_awg.i1;
    size_t n = 0;
    if (!p) return 0;

    while (*p) {
        while (isspace((unsigned char)*p)) p++;
        if (!*p) break;
        if (*p != '<') return 0;
        p++;
        while (isspace((unsigned char)*p)) p++;

        char name[3] = {0};
        int ni = 0;
        while (isalpha((unsigned char)*p) && ni < 2) name[ni++] = tolower((unsigned char)*p++);
        while (isspace((unsigned char)*p)) p++;

        if (!strcmp(name, "b")) {
            if (p[0] != '0' || (p[1] != 'x' && p[1] != 'X')) return 0;
            p += 2;
            while (hexval(p[0]) >= 0 && hexval(p[1]) >= 0) {
                if (n >= max) return 0;
                out[n++] = (uint8_t)(hexval(p[0]) << 4 | hexval(p[1]));
                p += 2;
            }
        } else if (!strcmp(name, "r") || !strcmp(name, "rc") || !strcmp(name, "rd")) {
            char *end;
            unsigned long cnt = strtoul(p, &end, 10);
            if (end == p || cnt > max || n + cnt > max) return 0;
            p = end;
            for (unsigned long i = 0; i < cnt; i++) {
                uint32_t r = esp_random();
                if (!strcmp(name, "r"))       out[n++] = (uint8_t)r;
                else if (!strcmp(name, "rd")) out[n++] = '0' + (r % 10);
                else {
                    uint32_t k = r % 52;
                    out[n++] = k < 26 ? 'a' + k : 'A' + (k - 26);
                }
            }
        } else if (!strcmp(name, "t")) {
            if (n + 4 > max) return 0;
            uint32_t t = (uint32_t)time(NULL);
            out[n++] = t >> 24; out[n++] = t >> 16; out[n++] = t >> 8; out[n++] = t;
        } else if (!strcmp(name, "c")) {
            if (n + 4 > max) return 0;
            uint32_t c = awg_counter++;
            out[n++] = c >> 24; out[n++] = c >> 16; out[n++] = c >> 8; out[n++] = c;
        } else {
            return 0;
        }
        while (isspace((unsigned char)*p)) p++;
        if (*p != '>') return 0;
        p++;
    }
    return n;
}
