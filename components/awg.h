/* AmneziaWG 2.0 support layer (static headers H1..H4 = 1..4, S1..S4,
 * Jc/Jmin/Jmax, I1). All values live in RAM only. */
#ifndef AWG_H
#define AWG_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint16_t jc, jmin, jmax;
    uint16_t s1, s2, s3, s4;
    char    *i1;          /* heap string, NULL if unset */
} awg_params_t;

extern awg_params_t g_awg;

/* returns 0 on success, -1 on unknown key / bad value */
int  awg_set_param(const char *key, const char *value);
void awg_i1_clear(void);
int  awg_i1_append(const char *chunk);   /* 0 ok, -1 no memory / too long */
void awg_wipe(void);                     /* zero everything */

/* Build the I1 signature packet. Returns length (0 = none / parse error). */
size_t awg_build_i1(uint8_t *out, size_t max);

#ifdef __cplusplus
}
#endif
#endif
