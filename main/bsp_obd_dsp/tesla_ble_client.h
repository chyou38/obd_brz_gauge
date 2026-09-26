#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Tesla BLE client (direct Bluetooth to the vehicle, NOT ELM327 / OBD-II).
 *
 * This is the Tesla-data counterpart of elm327_ble_client.c. It connects
 * straight to a Tesla vehicle's GATT service, performs the (scaffolded)
 * key-auth handshake, and pushes decoded vehicle signals into the shared
 * obd_data_cache. The LVGL UI and theme system are unchanged.
 *
 * Status of this branch (tesla-ble):
 *   - Scan / connect / GATT service discovery: implemented.
 *   - Key provisioning & authenticated session: TODO (see docs/TESLA_BLUETOOTH.md).
 *   - Speed (km/h) decode: wired into obd_data_set_speed(); protobuf parsing
 *     is the next TODO once an authenticated session exists.
 *   - All other signals (RPM, temps, gear, ...): intentionally not wired yet.
 *
 * References:
 *   - yoziru/tesla-ble            (ESP32 Arduino BLE protocol library)
 *   - 0Bu/tesla-key-esp32         (ESP32 Tesla key reference)
 *   - teslamotors/vehicle-command (official protobuf / auth flow)
 */

typedef struct {
    void (*on_connected)(void);     // GATT link up (before auth)
    void (*on_disconnected)(void);   // GATT link down
    void (*on_speed_kmh)(uint8_t kmh); // decoded vehicle speed
} tesla_ble_callbacks_t;

/*
 * Initialize Bluedroid + GATT client and start scanning for a Tesla.
 * vehicle_vin may be NULL to connect to the first Tesla advertisement seen;
 * pass a VIN (or its tail) to lock onto a specific car.
 * Must be called after nvs_flash_init() and once only.
 */
void tesla_ble_init_and_start(const char *vehicle_vin,
                              const tesla_ble_callbacks_t *cbs);

/* Connection state query. */
bool tesla_ble_is_connected(void);

/* Drop the link (auto-reconnect is managed internally). */
void tesla_ble_disconnect(void);

#ifdef __cplusplus
}
#endif
