# FlyingHoneyBadger

**Wireless Discovery & Assessment Tool Suite**

A comprehensive, modular toolkit for passive WiFi discovery, RF mapping, cellular base station detection, Bluetooth scanning, and continuous wireless security monitoring. Built for security professionals, network administrators, and researchers.

## Modules

| Module | Codename | Description |
|--------|----------|-------------|
| WiFi Scanner | **HoneyBadger Core** | Passive 802.11 packet capture with channel hopping and monitor mode |
| RF Mapping | **WarrenMap** | Signal heatmaps, Folium/Leaflet maps, KML export for Google Earth |
| Analysis | **HoneyView** | Post-hoc analytics: evil twin detection, pattern analysis, HTML reports |
| Monitoring | **SentryWeb** | Continuous rogue AP detection, encryption downgrade alerts, policy engine |
| Positioning | **BadgerTrack** | Indoor positioning via GPS + IMU sensor fusion |
| Bluetooth | **BlueScout** | Passive Bluetooth/BLE scanning via Ubertooth |
| Cellular | **CellGuard** | GSM/LTE/5G NR tower detection, IMSI catcher / Stingray detection via SDR |

## Features

- **Passive scanning** - Receive-only by default, no transmission
- **Multi-band** - 2.4 GHz, 5 GHz WiFi, Bluetooth, GSM/LTE/5G cellular
- **Rogue detection** - Unauthorized APs, evil twins, encryption downgrades, fake cell towers
- **7 IMSI catcher heuristics** - Unknown cell ID, signal anomaly, encryption downgrade, frequency anomaly, LAC/TAC change, operator mismatch, rapid appearance
- **Encrypted storage** - AES-256-GCM file encryption, optional SQLCipher database encryption
- **Tamper-evident audit** - HMAC-SHA256 chained append-only audit log
- **Export** - CSV, JSON, KML with optional encryption
- **Desktop GUI** - PyQt6 tabbed interface with real-time updates
- **CLI** - Full-featured `fhb` command with subcommands for all operations

## Installation

### Basic (WiFi only)

```bash
pip install flyinghoneybadger
```

### Full (all modules)

```bash
pip install "flyinghoneybadger[all]"
```

### Development

```bash
git clone https://github.com/iHBV/FlyingHoneyBadger.git
cd FlyingHoneyBadger
pip install -e ".[dev,all]"
```

### Optional Extras

```bash
pip install "flyinghoneybadger[gui]"          # PyQt6 desktop GUI
pip install "flyinghoneybadger[gps]"          # GPS via gpsd
pip install "flyinghoneybadger[bluetooth]"    # Ubertooth Bluetooth scanning
pip install "flyinghoneybadger[cellular]"     # HackRF cellular scanning
pip install "flyinghoneybadger[encrypted_db]" # SQLCipher database encryption
```

### System Dependencies (for cellular/SDR)

```bash
# Debian/Ubuntu
sudo apt install gr-gsm hackrf rtl-sdr srsran
```

## Quick Start

### Scan WiFi networks

```bash
# Start a WiFi scan (requires monitor mode interface)
fhb scan start -i wlan0mon

# Scan with 5 GHz channels
fhb scan start -i wlan0mon --5ghz

# Export results
fhb export csv session.db -o results.csv
fhb export json session.db -o results.json --encrypt
```

### Cellular scanning (CellGuard)

```bash
# Scan for cell towers
fhb cellular scan --duration 60 --gsm --lte

# Save known-good tower baseline
fhb cellular baseline baseline.json --duration 120

# Detect rogue base stations
fhb cellular detect --baseline baseline.json --duration 300
```

### Continuous monitoring (SentryWeb)

```bash
# Monitor with rogue AP detection
fhb monitor start -i wlan0mon --known-aps authorized.txt

# View alerts
fhb monitor alerts
```

### Audit trail

```bash
# Verify audit log integrity
fhb audit verify

# View recent audit entries
fhb audit show -n 20

# Export audit log
fhb audit export -o audit_report.json
```

### Desktop GUI

```bash
fhb gui
```

## Hardware Support

| Device | Purpose | Module |
|--------|---------|--------|
| Any monitor-mode WiFi adapter | WiFi scanning | HoneyBadger Core |
| NooElec NESDR Nano 3 (RTL-SDR) | GSM tower scanning | CellGuard |
| PortaPack H4M (HackRF One) | LTE/5G cell search | CellGuard |
| Ubertooth One | Bluetooth scanning | BlueScout |
| USB GPS (via gpsd) | Geolocation | WarrenMap / BadgerTrack |
| Raspberry Pi CM5 | Deployment platform | All modules |

## Architecture

```
flyinghoneybadger/
├── core/           # WiFi packet capture, parsing, scanning engine
├── analysis/       # Post-hoc analytics, pattern detection, reporting
├── bluetooth/      # Bluetooth/BLE scanning via Ubertooth
├── cellular/       # Cellular tower detection via SDR (CellGuard)
├── db/             # SQLAlchemy database persistence
├── gui/            # PyQt6 desktop application
├── mapping/        # GIS utilities, signal heatmaps, KML export
├── monitoring/     # Continuous monitoring, alerting, policy engine
├── positioning/    # Indoor positioning via GPS/IMU fusion
├── utils/          # Configuration, logging, crypto, audit
└── cli/            # Click CLI commands
```

## Configuration

Default configuration is in `data/default_config.yaml`. User config is loaded from `~/.config/flyinghoneybadger/config.yaml`.

Key settings:

```yaml
scan:
  interface: "wlan0mon"
  hop_interval: 0.5
  scan_5ghz: true

cellular:
  enabled: true
  scan_gsm: true
  scan_lte: true

security:
  audit_enabled: true
  encrypt_exports: false
  encrypt_database: false

monitoring:
  alert_on_rogue_ap: true
```

## Testing

```bash
python -m pytest tests/ -v
```

## License

[MIT](LICENSE)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and guidelines.

## Security

See [SECURITY.md](SECURITY.md) for the security policy and vulnerability reporting.
