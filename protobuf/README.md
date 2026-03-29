# aap_protobuf

Protocol Buffer definitions for the Android Auto Protocol (AAP) v1.6, compiled as a standalone CMake library consumed by [aasdk](https://github.com/sjdean/aasdk).

This directory contains 254 `.proto` files covering all AAP service channels, reverse-engineered from the Android Auto binary and documented by **milek7** at [milek7.pl/.stuff/galdocs/](https://milek7.pl/.stuff/galdocs/readme.md).

---

## Directory structure

```
aap_protobuf/
├── aaw/                        # Android Auto WiFi
├── channel/
│   └── control/                # Handshake, version, service discovery
├── service/
│   ├── bluetooth/message/
│   ├── control/message/
│   ├── genericnotification/message/
│   ├── inputsource/message/
│   ├── media/
│   │   ├── sink/message/       # Audio/video sink (HU receives)
│   │   ├── source/message/     # Audio source (HU sends)
│   │   ├── video/message/
│   │   └── shared/message/     # Ack, config shared across media channels
│   ├── mediabrowser/message/
│   ├── mediaplayback/message/
│   ├── navigationstatus/message/
│   ├── phonestatus/message/
│   ├── radio/message/
│   ├── sensorsource/message/
│   ├── vendorextension/
│   └── wifiprojection/message/
└── shared/                     # PhoneInfo, MessageStatus (cross-service types)
```

---

## Build

The protobuf library is built and installed separately so that aasdk can locate it via `find_package(aap_protobuf CONFIG REQUIRED)`.

```bash
mkdir protobuf/build
cd protobuf/build
cmake -DCMAKE_BUILD_TYPE=Release ..
make
sudo make install
```

---

## Credits

Protocol definitions derived from the research and reverse-engineering work of **milek7**:
[Android Auto Protocol research (GAL docs)](https://milek7.pl/.stuff/galdocs/readme.md)

*Android Auto is a registered trademark of Google Inc.*