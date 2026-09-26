# tesla-ble branch

This branch is a Tesla-only variant of `obd_brz_gauge`.

- **Connection**: direct Bluetooth Low Energy to the Tesla vehicle —
  **no ELM327 / OBD-II adapter**.
- **Hardware**: unchanged — Waveshare ESP32-S3-Touch-LCD-1.85 (360×360 round).
- **UI / themes**: unchanged. Everything under `themes/` (builtin `default`,
  `ocean`, `amber`, community themes, `_TEMPLATE`) is carried over as-is and
  continues to work.
- **Data**: only vehicle speed (km/h) is wired up for now. Other signals are
  intentionally not implemented yet and will be added incrementally.

## New files on this branch

- `main/bsp_obd_dsp/tesla_ble_client.{c,h}` — BLE GATT client to the car.
- `docs/TESLA_BLUETOOTH.md` — pairing/auth/protocol notes and TODO list.

## Build

Same as upstream:

```
git checkout tesla-ble
idf.py set-target esp32s3
idf.py build
idf.py -p PORT flash monitor
```

See upstream `README.md` for hardware and flashing details. Themes are built
the same way; nothing theme-related has changed.
