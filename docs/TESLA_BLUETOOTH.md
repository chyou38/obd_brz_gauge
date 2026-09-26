# Tesla Bluetooth (BLE) adaptation

Direct BLE link to a Tesla vehicle. No ELM327 / OBD-II adapter.
Hardware, LVGL UI, themes, and ESP-NOW multi-gauge are unchanged.

## Protocol (implemented in tesla_ble_client.c)

1. Long-term P-256 key generated on first boot, stored as PEM in NVS.
2. Connect to GATT service 0x211, write char 0x212, notify char 0x213.
3. Send SessionInfoRequest with our public key.
4. Car replies SessionInfo (car ephemeral pubkey, epoch, counter).
5. ECDH(our_priv, car_pub) -> X; AES-128 key = SHA1(X)[0:16].
6. Send GetVehicleData(getDriveState) AES-128-GCM encrypted.
7. Decrypt response, pull drive_state.speed (km/h), obd_data_set_speed().

## One-time key whitelisting

In the Tesla mobile app: Security -> Bluetooth Key -> Add, then tap the
module against the car's BLE reader. See 0Bu/tesla-key-esp32.

## Build step: nanopb generated code

Generate nanopb .pb.c/.pb.h from teslamotors/vehicle-command protos into
main/proto/, then implement the four tesla_proto_* shims declared in
tesla_ble_client.c. The crypto and BLE layers are already complete.

## Signals

- Speed (km/h): wired.
- TODO: gear, SOC, power, odometer.
