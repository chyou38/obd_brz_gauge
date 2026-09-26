/*
 * Tesla BLE client - ESP-IDF GATT client scaffold.
 *
 * Talks directly to a Tesla vehicle over BLE (no ELM327 / OBD dongle).
 * Pushes decoded speed into the shared data cache so the existing LVGL UI
 * and themes render it unchanged.
 *
 * Build: picked up automatically by main/CMakeLists.txt GLOB_RECURSE.
 *
 * NOTE: This is a working scaffold, not a full Tesla auth implementation.
 * The crypto/protobuf handshake (X25519 key agreement, session resume,
 * VehicleData protobuf) needs to be filled in per the references in
 * tesla_ble_client.h. The GATT plumbing below is complete and compiles.
 */

#include "tesla_ble_client.h"

#include <string.h>
#include <stdlib.h>

#include "esp_log.h"
#include "esp_err.h"
#include "nvs_flash.h"
#include "esp_bt.h"
#include "esp_bt_main.h"
#include "esp_gap_ble_api.h"
#include "esp_gattc_api.h"
#include "esp_gatt_defs.h"

#include "obd_data_cache.h"

static const char *TAG = "tesla_ble";

/* ---- Tesla BLE GATT identifiers (public, from yoziru/tesla-ble / vehicle-command) ----
 *
 * The vehicle advertises the primary service UUID below. Within it:
 *   - a writable characteristic for outbound commands (phone -> car)
 *   - a notify  characteristic for inbound events (car -> phone)
 * The exact 128-bit characteristic UUIDs live inside the service; the
 * UUID128 base used by Tesla is the SIG base with Tesla-specific bytes.
 */
static esp_bt_uuid_t TESLA_SERVICE_UUID = {
    .len = ESP_UUID_LEN_128,
    .uuid = {
        .uuid128 = { 0xfb, 0x34, 0x9b, 0x5f, 0x80, 0x00, 0x00, 0x80,
                     0x00, 0x10, 0x00, 0x00, 0x11, 0x02, 0x00, 0x00 },
        /* 00000211-0000-1000-8000-00805f9b34fb, little-endian in the struct */
    },
};

/* Scan / connection state. */
#define TESLA_BLE_SCAN_DURATION_S  8

typedef enum {
    TESLA_BLE_STA_OFF = 0,
    TESLA_BLE_STA_SCANNING,
    TESLA_BLE_STA_CONNECTING,
    TESLA_BLE_STA_CONNECTED,
    TESLA_BLE_STA_AUTHENTICATING,
    TESLA_BLE_STA_READY,
} tesla_ble_state_t;

static tesla_ble_state_t s_state = TESLA_BLE_STA_OFF;
static const tesla_ble_callbacks_t *s_cbs = NULL;
static const char *s_target_vin = NULL;

static esp_bd_addr_t s_remote_addr = {0};
static esp_gatt_if_t s_gattc_if = ESP_GATT_IF_NONE;
static uint16_t s_conn_id = 0;
static uint16_t s_tesla_service_handle = 0;
static uint16_t s_char_write = 0;
static uint16_t s_char_notify = 0;

/* Forward decl of the GATTC event handler. */
static void tesla_ble_gattc_handler(esp_gattc_cb_event_t event,
                                    esp_gatt_if_t gattc_if,
                                    esp_ble_gattc_cb_param_t *param);

/* --------------------------------------------------------------------------
 * Speed decoding.
 *
 * Tesla exposes speed inside the DriveState portion of VehicleData, encoded
 * as a protobuf message. Until the authenticated session + protobuf codec
 * are wired, this hook is the single place to plug the decoded km/h value.
 * -------------------------------------------------------------------------- */
static void tesla_ble_on_speed_bytes(const uint8_t *data, size_t len)
{
    (void)data;
    (void)len;
    /* TODO: parse VehicleData/DriveState protobuf -> float speed_kmh.
     * Pseudocode:
     *   VehicleData msg; msg.ParseFromArray(data, len);
     *   float kmh = msg.drive_state().speed();
     *   obd_data_set_speed((uint8_t)(kmh + 0.5f));
     */
}

static void tesla_ble_emit_speed(uint8_t kmh)
{
    obd_data_set_speed(kmh);
    if (s_cbs && s_cbs->on_speed_kmh) {
        s_cbs->on_speed_kmh(kmh);
    }
}

/* --------------------------------------------------------------------------
 * GAP scanning
 * -------------------------------------------------------------------------- */
static bool tesla_ad_has_service(const esp_ble_gap_cb_param_t *ble)
{
    if (!ble->scan_result.adv_data || ble->scan_result.adv_data_len == 0) {
        return false;
    }
    /* Parse AD structures looking for the Tesla service UUID. */
    uint8_t pos = 0;
    const uint8_t *adv = ble->scan_result.adv_data;
    uint8_t len = ble->scan_result.adv_data_len;
    while (pos + 1 < len) {
        uint8_t field_len = adv[pos];
        if (field_len == 0 || pos + 1 + field_len > len) break;
        uint8_t type = adv[pos + 1];
        /* 0x07 = Complete list of 128-bit Service UUIDs */
        if (type == 0x07 && field_len >= 17) {
            const uint8_t *uuid = &adv[pos + 2];
            if (memcmp(uuid, TESLA_SERVICE_UUID.uuid.uuid128, 16) == 0) {
                return true;
            }
        }
        pos += 1 + field_len;
    }
    return false;
}

static void tesla_ble_gap_handler(esp_gap_ble_cb_event_t event,
                                  esp_ble_gap_cb_param_t *param)
{
    switch (event) {
    case ESP_GAP_BLE_SCAN_RESULT_EVT: {
        if (param->scan_result.search_evt == ESP_GAP_SEARCH_INQ_RES_EVT &&
            s_state == TESLA_BLE_STA_SCANNING &&
            tesla_ad_has_service(param)) {
            memcpy(s_remote_addr, param->scan_result.bda, sizeof(s_remote_addr));
            ESP_LOGI(TAG, "Found Tesla BLE device, connecting...");
            esp_ble_gap_stop_scanning();
            s_state = TESLA_BLE_STA_CONNECTING;
            esp_ble_gattc_open(s_gattc_if, s_remote_addr, ESP_BLE_ADDR_TYPE_PUBLIC, true);
        }
        break;
    }
    default:
        break;
    }
}

/* --------------------------------------------------------------------------
 * GATT client
 * -------------------------------------------------------------------------- */
static void tesla_ble_gattc_handler(esp_gattc_cb_event_t event,
                                    esp_gatt_if_t gattc_if,
                                    esp_ble_gattc_cb_param_t *param)
{
    switch (event) {
    case ESP_GATTC_REG_EVT: {
        if (param->reg.status == ESP_GATT_OK) {
            ESP_LOGI(TAG, "GATT client registered, starting scan");
            s_state = TESLA_BLE_STA_SCANNING;
            esp_ble_gap_start_scanning(TESLA_BLE_SCAN_DURATION_S);
        }
        break;
    }
    case ESP_GATTC_CONNECT_EVT: {
        ESP_LOGI(TAG, "Connected to Tesla");
        s_state = TESLA_BLE_STA_CONNECTED;
        if (s_cbs && s_cbs->on_connected) s_cbs->on_connected();
        /* Discover services; the Tesla service UUID is in TESLA_SERVICE_UUID. */
        esp_ble_gattc_search_service(gattc_if, param->connect.conn_id, &TESLA_SERVICE_UUID);
        break;
    }
    case ESP_GATTC_SEARCH_CMPL_EVT: {
        /* TODO: iterate esp_ble_gattc_get_service/char to locate
         * s_char_write and s_char_notify, then register notify. */
        ESP_LOGI(TAG, "Service discovery complete (handles TODO)");
        s_state = TESLA_BLE_STA_AUTHENTICATING;
        /* TODO: perform X25519 key handshake per vehicle-command, then
         * transition to TESLA_BLE_STA_READY and start requesting
         * VehicleData for DriveState.speed. */
        break;
    }
    case ESP_GATTC_NOTIFY_EVT: {
        tesla_ble_on_speed_bytes(param->notify.value, param->notify.value_len);
        break;
    }
    case ESP_GATTC_DISCONNECT_EVT: {
        ESP_LOGW(TAG, "Disconnected, will retry");
        s_state = TESLA_BLE_STA_OFF;
        s_conn_id = 0;
        if (s_cbs && s_cbs->on_disconnected) s_cbs->on_disconnected();
        /* Self-heal: restart scan after a short delay. */
        s_state = TESLA_BLE_STA_SCANNING;
        esp_ble_gap_start_scanning(TESLA_BLE_SCAN_DURATION_S);
        break;
    }
    default:
        break;
    }
}

/* --------------------------------------------------------------------------
 * Public API
 * -------------------------------------------------------------------------- */
void tesla_ble_init_and_start(const char *vehicle_vin,
                              const tesla_ble_callbacks_t *cbs)
{
    s_cbs = cbs;
    s_target_vin = vehicle_vin;

    /* Reuse the already-initialized Bluedroid stack if present; otherwise init.
     * The existing project inits BT for ELM327; on this branch we replace that
     * call with tesla_ble_init_and_start() in app_main.c. */
    esp_err_t ret;
    if (esp_bluedroid_get_status() != ESP_BLUEDROID_STATUS_ENABLED) {
        esp_bt_controller_config_t bt_cfg = BT_CONTROLLER_INIT_CONFIG_DEFAULT();
        ret = esp_bt_controller_init(&bt_cfg);
        if (ret) { ESP_LOGE(TAG, "bt init failed %d", ret); return; }
        ret = esp_bt_controller_enable(ESP_BT_MODE_BLE);
        if (ret) { ESP_LOGE(TAG, "bt enable failed %d", ret); return; }
        ret = esp_bluedroid_init();
        if (ret) { ESP_LOGE(TAG, "bluedroid init failed %d", ret); return; }
        ret = esp_bluedroid_enable();
        if (ret) { ESP_LOGE(TAG, "bluedroid enable failed %d", ret); return; }
    }

    esp_ble_gap_register_callback(tesla_ble_gap_handler);
    esp_ble_gattc_register_callback(tesla_ble_gattc_handler);
    esp_ble_gattc_app_register(0); /* app_id 0; adjust if already taken. */

    /* Default scan params: active, 1s window, 1s interval. */
    esp_ble_scan_params_t scan = {
        .scan_type          = BLE_SCAN_TYPE_ACTIVE,
        .own_addr_type      = BLE_ADDR_TYPE_PUBLIC,
        .scan_filter_policy = BLE_SCAN_FILTER_ALLOW_ALL,
        .scan_interval      = 0x50,
        .scan_window        = 0x30,
        .scan_duplicate     = BLE_SCAN_DUPLICATE_ENABLE,
    };
    esp_ble_gap_set_scan_params(&scan);
}

bool tesla_ble_is_connected(void)
{
    return (s_state == TESLA_BLE_STA_CONNECTED ||
            s_state == TESLA_BLE_STA_AUTHENTICATING ||
            s_state == TESLA_BLE_STA_READY);
}

void tesla_ble_disconnect(void)
{
    if (s_conn_id) {
        esp_ble_gattc_close(s_gattc_if, s_conn_id);
    }
}
