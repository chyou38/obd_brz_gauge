/*
 * Tesla BLE client - ESP-IDF implementation.
 * Crypto is mbedtls (already in REQUIRES). Protobuf framing uses nanopb.
 * See docs/TESLA_BLUETOOTH.md for the generated .pb files step.
 */
#include "tesla_ble_client.h"
#include <string.h>
#include <stdlib.h>
#include "esp_log.h"
#include "esp_err.h"
#include "esp_timer.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "esp_bt.h"
#include "esp_bt_main.h"
#include "esp_gap_ble_api.h"
#include "esp_gattc_api.h"
#include "esp_gatt_defs.h"
#include "mbedtls/platform.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/pk.h"
#include "mbedtls/ecp.h"
#include "mbedtls/sha1.h"
#include "mbedtls/sha256.h"
#include "mbedtls/gcm.h"
#include "obd_data_cache.h"

static const char *TAG = "tesla_ble";

/* Service 0x211, TX(write) 0x212, RX(notify) 0x213, little-endian */
static esp_bt_uuid_t UUID_SVC = { .len = ESP_UUID_LEN_128,
    .uuid.uuid128 = {0xfb,0x34,0x9b,0x5f,0x80,0x00,0x00,0x80,0x00,0x10,0x00,0x00,0x11,0x02,0x00,0x00} };
static esp_bt_uuid_t UUID_TX  = { .len = ESP_UUID_LEN_128,
    .uuid.uuid128 = {0xfb,0x34,0x9b,0x5f,0x80,0x00,0x00,0x80,0x00,0x10,0x00,0x00,0x12,0x02,0x00,0x00} };
static esp_bt_uuid_t UUID_RX  = { .len = ESP_UUID_LEN_128,
    .uuid.uuid128 = {0xfb,0x34,0x9b,0x5f,0x80,0x00,0x00,0x80,0x00,0x10,0x00,0x00,0x13,0x02,0x00,0x00} };

typedef enum { ST_OFF=0, ST_SCAN, ST_CONNECTING, ST_CONNECTED,
                ST_SESSION_REQ_SENT, ST_AUTHED } st_t;
static st_t s_state = ST_OFF;
static const tesla_ble_callbacks_t *s_cbs;
static char s_vin[18];
static esp_gatt_if_t s_gattc_if;
static uint16_t s_conn_id, s_tx_handle, s_rx_handle;
static esp_bd_addr_t s_remote;

static mbedtls_pk_context s_our_key;
static mbedtls_entropy_context s_entropy;
static mbedtls_ctr_drbg_context s_drbg;
static bool s_key_loaded;
static uint8_t s_aes_key[16], s_epoch[16], s_connection_id[16];
static uint32_t s_counter, s_clock_time;

static int crypto_init(void) {
    mbedtls_pk_init(&s_our_key);
    mbedtls_entropy_init(&s_entropy);
    mbedtls_ctr_drbg_init(&s_drbg);
    return mbedtls_ctr_drbg_seed(&s_drbg, mbedtls_entropy_func, &s_entropy, NULL, 0);
}

static int crypto_load_or_create_key(void) {
    if (s_key_loaded) return 0;
    nvs_handle_t h; size_t len = 1024;
    char *pem = calloc(1, len);
    int r = nvs_open("tesla_key", NVS_READONLY, &h);
    if (r == ESP_OK) { r = nvs_get_blob(h, "priv_pem", pem, &len); nvs_close(h); }
    if (r == ESP_OK) {
        r = mbedtls_pk_parse_key(&s_our_key, (uint8_t*)pem, len, NULL, 0,
                                 mbedtls_ctr_drbg_random, &s_drbg);
        free(pem);
        if (r == 0 && mbedtls_pk_can_do(&s_our_key, MBEDTLS_PK_ECKEY)) {
            s_key_loaded = true; ESP_LOGI(TAG, "Loaded P-256 key from NVS"); return 0;
        }
        mbedtls_pk_free(&s_our_key); mbedtls_pk_init(&s_our_key);
    } else { free(pem); }
    ESP_LOGI(TAG, "Generating new P-256 keypair...");
    r = mbedtls_pk_setup(&s_our_key, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
    if (r) return r;
    r = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, mbedtls_pk_ec(s_our_key),
                            mbedtls_ctr_drbg_random, &s_drbg);
    if (r) return r;
    pem = calloc(1, 1024);
    if (mbedtls_pk_write_key_pem(&s_our_key, (uint8_t*)pem, 1024) == 0) {
        size_t l = strlen(pem)+1;
        nvs_open("tesla_key", NVS_READWRITE, &h);
        nvs_set_blob(h, "priv_pem", pem, l); nvs_commit(h); nvs_close(h);
    }
    free(pem); s_key_loaded = true;
    return 0;
}

bool tesla_ble_get_public_key(uint8_t *out65, size_t *outlen) {
    if (!s_key_loaded) return false;
    mbedtls_ecp_keypair *k = mbedtls_pk_ec(s_our_key);
    size_t olen = 65;
    if (mbedtls_ecp_point_write_binary(&k->grp, &k->Q, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                       &olen, out65, 65)) return false;
    *outlen = olen; return true;
}

static int crypto_ecdh_session_key(const uint8_t *car_pub65) {
    mbedtls_ecp_point cp; mbedtls_ecp_point_init(&cp);
    mbedtls_ecp_point sp; mbedtls_ecp_point_init(&sp);
    mbedtls_ecp_keypair *k = mbedtls_pk_ec(s_our_key);
    int r = mbedtls_ecp_point_read_binary(&k->grp, &cp, car_pub65, 65);
    if (r) goto out;
    r = mbedtls_ecp_mul(&k->grp, &sp, &k->d, &cp, mbedtls_ctr_drbg_random, &s_drbg);
    if (r) goto out;
    uint8_t sx[32];
    r = mbedtls_mpi_write_binary(&sp.X, sx, 32);
    if (r) goto out;
    uint8_t sha1[20]; mbedtls_sha1(sx, 32, sha1, 0);
    memcpy(s_aes_key, sha1, 16);
    mbedtls_platform_zeroize(sx, sizeof(sx));
    ESP_LOGI(TAG, "ECDH OK, AES-128 key derived");
out:
    mbedtls_ecp_point_free(&cp); mbedtls_ecp_point_free(&sp);
    return r;
}

/* nanopb shims - implemented in main/proto/ after codegen. */
extern int tesla_proto_build_session_info_request(uint8_t*,size_t,size_t*,
                                                  const uint8_t*,const uint8_t*);
extern int tesla_proto_build_get_drive_state(uint8_t*,size_t,size_t*,
                                              const char*,uint32_t,uint32_t,
                                              const uint8_t*,const uint8_t*,
                                              const uint8_t*,uint8_t*,uint8_t*);
extern int tesla_proto_parse_notify(const uint8_t*,size_t,const char*,
                                    uint8_t*,uint8_t*,uint32_t*,
                                    uint8_t*,size_t,size_t*);
extern int tesla_proto_extract_speed_kmh(const uint8_t*,size_t);

static void ble_send(const uint8_t *d, size_t n) {
    esp_ble_gattc_write_char(s_gattc_if, s_conn_id, s_tx_handle, n, (uint8_t*)d,
                             ESP_GATT_WRITE_TYPE_NO_RSP, ESP_GATT_AUTH_REQ_NONE);
}

static void start_handshake(void) {
    uint8_t pub65[65]; size_t pl;
    if (!tesla_ble_get_public_key(pub65, &pl)) return;
    static uint8_t msg[512]; size_t ml;
    if (tesla_proto_build_session_info_request(msg, sizeof(msg), &ml, pub65, s_connection_id)) return;
    s_state = ST_SESSION_REQ_SENT;
    ble_send(msg, ml);
}

static void request_drive(void) {
    static uint8_t msg[512]; size_t ml;
    uint8_t nonce[12], tag[16];
    uint32_t exp = s_clock_time + 5;
    if (tesla_proto_build_get_drive_state(msg, sizeof(msg), &ml, s_vin,
                ++s_counter, exp, s_epoch, s_aes_key, s_connection_id, nonce, tag)) return;
    ble_send(msg, ml);
}

static void on_notify(const uint8_t *data, size_t len) {
    if (len < 2) return;
    uint16_t mlen = ((uint16_t)data[0]<<8) | data[1];
    const uint8_t *pb = data+2;
    if (mlen > len-2) mlen = len-2;
    uint8_t car_pub[65], epoch[16], plain[256];
    uint32_t counter = 0; size_t plen = 0;
    if (tesla_proto_parse_notify(pb, mlen, s_vin, car_pub, epoch, &counter,
                                 plain, sizeof(plain), &plen)) return;
    if (s_state == ST_SESSION_REQ_SENT && car_pub[0] == 0x04) {
        crypto_ecdh_session_key(car_pub);
        memcpy(s_epoch, epoch, 16); s_counter = counter;
        s_state = ST_AUTHED;
        request_drive();
    } else if (s_state == ST_AUTHED && plen) {
        int sp = tesla_proto_extract_speed_kmh(plain, plen);
        if (sp >= 0) { obd_data_set_speed((uint8_t)sp); if (s_cbs&&s_cbs->on_speed_kmh) s_cbs->on_speed_kmh((uint8_t)sp); }
        vTaskDelay(pdMS_TO_TICKS(1000));
        request_drive();
    }
}

static bool adv_is_tesla(const esp_ble_gap_cb_param_t *e) {
    const uint8_t *d = e->scan_result.adv_data; int pos=0, len=e->scan_result.adv_data_len;
    while (pos+1 < len) { int fl=d[pos]; if(!fl||pos+1+fl>len) break;
        if (d[pos+1]==0x07 && fl>=17 && memcmp(&d[pos+2],UUID_SVC.uuid.uuid128,16)==0) return true;
        pos += 1+fl; } return false;
}

static void gap_cb(esp_gap_ble_cb_event_t ev, esp_ble_gap_cb_param_t *p) {
    if (ev==ESP_GAP_BLE_SCAN_RESULT_EVT && p->scan_result.search_evt==ESP_GAP_SEARCH_INQ_RES_EVT
        && s_state==ST_SCAN && adv_is_tesla(p)) {
        memcpy(s_remote, p->scan_result.bda, 6);
        esp_ble_gap_stop_scanning(); s_state=ST_CONNECTING;
        esp_ble_gattc_open(s_gattc_if, s_remote, ESP_BLE_ADDR_TYPE_PUBLIC, true);
    }
}

static void gattc_cb(esp_gattc_cb_event_t ev, esp_gatt_if_t iface, esp_ble_gattc_cb_param_t *p) {
    switch (ev) {
    case ESP_GATTC_REG_EVT: s_gattc_if=iface; s_state=ST_SCAN; esp_ble_gap_start_scanning(10); break;
    case ESP_GATTC_CONNECT_EVT:
        s_conn_id=p->connect.conn_id; s_state=ST_CONNECTED;
        if (s_cbs&&s_cbs->on_connected) s_cbs->on_connected();
        esp_ble_gattc_search_service(iface, s_conn_id, &UUID_SVC); break;
    case ESP_GATTC_SEARCH_CMPL_EVT: {
        uint16_t count=0, got=0;
        esp_gattc_char_elem_t ch[8];
        esp_ble_gattc_get_attr_count(iface, s_conn_id, ESP_GATT_DB_CHAR, 0,0,&count);
        for (uint16_t i=0; i<count && got<8; i++) {
            if (esp_ble_gattc_get_all_char(iface, s_conn_id, 0,0, &ch[got], &(uint16_t){1})!=ESP_OK) break;
            if (ch[got].uuid.len==ESP_UUID_LEN_128) {
                if (!memcmp(ch[got].uuid.uuid.uuid128,UUID_TX.uuid.uuid128,16)) s_tx_handle=ch[got].char_handle;
                if (!memcmp(ch[got].uuid.uuid.uuid128,UUID_RX.uuid.uuid128,16)) {
                    s_rx_handle=ch[got].char_handle;
                    uint16_t cccd=1;
                    esp_ble_gattc_write_char_descr(iface, s_conn_id, s_rx_handle+1, 2,(uint8_t*)&cccd,
                                                   ESP_GATT_WRITE_TYPE_RSP, ESP_GATT_AUTH_REQ_NONE);
                }
            }
            got++;
        }
        start_handshake(); break;
    }
    case ESP_GATTC_NOTIFY_EVT: on_notify(p->notify.value, p->notify.value_len); break;
    case ESP_GATTC_DISCONNECT_EVT:
        s_state=ST_SCAN;
        if (s_cbs&&s_cbs->on_disconnected) s_cbs->on_disconnected();
        esp_ble_gap_start_scanning(10); break;
    default: break;
    }
}

void tesla_ble_init_and_start(const char *vin, const tesla_ble_callbacks_t *cbs) {
    s_cbs = cbs;
    if (vin) { strncpy(s_vin, vin, 17); s_vin[17]=0; }
    crypto_init(); crypto_load_or_create_key();
    mbedtls_ctr_drbg_random(&s_drbg, s_connection_id, 16);
    if (esp_bluedroid_get_status()!=ESP_BLUEDROID_STATUS_ENABLED) {
        esp_bt_controller_config_t bc=BT_CONTROLLER_INIT_CONFIG_DEFAULT();
        esp_bt_controller_init(&bc); esp_bt_controller_enable(ESP_BT_MODE_BLE);
        esp_bluedroid_init(); esp_bluedroid_enable();
    }
    esp_ble_gap_register_callback(gap_cb);
    esp_ble_gattc_register_callback(gattc_cb);
    esp_ble_gattc_app_register(0);
    esp_ble_scan_params_t sp = {
        .scan_type=BLE_SCAN_TYPE_ACTIVE, .own_addr_type=BLE_ADDR_TYPE_PUBLIC,
        .scan_filter_policy=BLE_SCAN_FILTER_ALLOW_ALL, .scan_interval=0x50,
        .scan_window=0x30, .scan_duplicate=BLE_SCAN_DUPLICATE_ENABLE };
    esp_ble_gap_set_scan_params(&sp);
}
bool tesla_ble_is_connected(void) { return s_state>=ST_CONNECTED; }
void tesla_ble_disconnect(void) { if (s_conn_id) esp_ble_gattc_close(s_gattc_if, s_conn_id); }
