# Tesla Bluetooth (BLE) adaptation

This branch (`tesla-ble`) replaces the ELM327/OBD data source with a direct
Bluetooth Low Energy link to a Tesla vehicle. The hardware, LVGL UI, and
theme system are unchanged — only the data source changes.

## What works today

- BLE scan for the Tesla vehicle-advertised service UUID
  (`00000211-0000-1000-8000-00805f9b34fb`).
- GATT client connect + service discovery plumbing.
- Speed is routed into the shared `obd_data_cache` via
  `obd_data_set_speed()`, so any theme's speed gauge renders it.
- Auto-reconnect when the link drops (self-healing, same as ELM327 path).

## What is not wired yet (TODO)

The hard part of Tesla BLE is **not** GATT — it's the authenticated command
session. Until that is implemented, speed will not actually update:

1. **Key provisioning** — generate an X25519 keypair on the device, share the
   public key with the car via the Tesla mobile app ("Bluetooth Key"), so the
   car recognizes this ESP32 as an authorized BLE key.
2. **Session handshake** — on connect, run the unauthenticated -> authenticated
   GATT security procedure (the `vehicle-command` protobuf `SecuredSession`).
3. **VehicleData request** — once authenticated, send a protobuf
   `VehicleDataRequest` for `drive_state` and read the notify response.
4. **Protobuf decode** — pull `drive_state.speed` (float, km/h) and call
   `tesla_ble_emit_speed()`.

Reference implementations:

| Repo | Use it for |
|---|---|
| `yoziru/tesla-ble` | Core BLE protocol library; most portable reference for ESP32. |
| `0Bu/tesla-key-esp32` | ESP32 Tesla Bluetooth key (provisioning flow). |
| `teslamotors/vehicle-command` | Official protobuf definitions and auth flow. |
| `yoziru/esphome-tesla-ble` | ESPHome integration (higher-level wiring). |
| `kaedenbrinkman/PyTeslaBLE` | Python BLE reference (useful for decoding). |

## Wiring into app_main

On this branch, instead of `elm327_ble_start_default(...)`, call:

```c
tesla_ble_callbacks_t cbs = {
    .on_connected   = NULL,
    .on_disconnected = NULL,
    .on_speed_kmh   = NULL,   // optional; cache is updated directly
};
tesla_ble_init_and_start(NULL, &cbs);
```

The ELM327 polling task should be disabled (or guarded by a compile-time
switch) so the BLE radio is not contended. The ESP-NOW multi-gauge path
still works: the master board reads Tesla speed and broadcasts to slaves.

## Vehicle profile

Use `OBD2 Generic` (or any profile) on this branch — the speed value comes
from Tesla, not from a PID. Other fields (RPM, temps, gear) read invalid
until corresponding Tesla signals are added.

## Next signals to add

Once speed is live, the order of likely additions is:

1. Speed (done / scaffolded)
2. Gear / drive state (`P/R/N/D`)
3. Battery SOC + power kW
4. Odometer

Each one is another `obd_data_set_*()` call from the notify decoder.
