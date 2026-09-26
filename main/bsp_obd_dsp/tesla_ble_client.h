#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    void (*on_connected)(void);
    void (*on_disconnected)(void);
    void (*on_speed_kmh)(uint8_t kmh);
} tesla_ble_callbacks_t;

void tesla_ble_init_and_start(const char *vin, const tesla_ble_callbacks_t *cbs);
bool tesla_ble_is_connected(void);
void tesla_ble_disconnect(void);
bool tesla_ble_get_public_key(uint8_t *out65, size_t *len);

#ifdef __cplusplus
}
#endif
