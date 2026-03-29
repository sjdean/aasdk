# aasdk

C++ library implementing the Android Auto Protocol (AAP) v1.6, providing everything needed to build headunit software: USB and TCP transport, SSL encryption, AOAP device management, and a full set of service channel implementations.

This project is a fork of the [f1x/aasdk](https://github.com/f1x-studio/aasdk) library originally authored by Michal Szwaj at f1x.studio, subsequently maintained by the [OpenCarDev / CrankShaft](https://github.com/opencardev) team, and substantially reworked here to implement Android Auto Protocol 1.6.

---

## Build

### Dependencies

```
cmake (>= 3.16)
build-essential
protobuf-compiler  libprotobuf-dev
libusb-1.0.0-dev
libssl-dev
libboost-dev  libboost-system-dev  libboost-log-dev
```

### Linux / Raspberry Pi

```bash
sudo apt-get update
sudo apt-get install -y cmake build-essential git \
    protobuf-compiler libprotobuf-dev libusb-1.0.0-dev \
    libssl-dev libboost-dev libboost-system-dev libboost-log-dev

git clone https://github.com/sjdean/aasdk
cd aasdk
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
sudo cmake --install build
```

### Raspberry Pi cross-compile

```bash
cmake -B build -DCMAKE_TOOLCHAIN_FILE=rpi-toolchain.cmake -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

### Unit tests

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Debug -DAASDK_TEST=ON
cmake --build build --target aasdk_ut
./build/aasdk_ut
```

---

## Supported functionalities

- Android Auto Protocol (AAP) v1.6
- AOAP (Android Open Accessory Protocol)
- USB transport
- TCP transport
- USB hotplug detection
- SSL/TLS encryption (OpenSSL)
- Async I/O via Boost.ASIO with promise-based channel handling
- CMake install targets and CPack Debian packaging
- Yocto / cross-compilation support

---

## Supported communication channels

| Channel | Description |
|---|---|
| Control | Handshake, version negotiation, service discovery, authentication |
| MediaSource (Audio) | Media, system, guidance and telephony audio source streams |
| MediaSink (Audio) | Audio capture from the head unit |
| MediaSink (Video) | Video rendering channel |
| InputSource | Touch events and button input |
| SensorSource | Accelerometer, gyroscope, compass, GPS |
| Bluetooth | Pairing and connectivity management |
| NavigationStatus | Navigation waypoints and status |
| PhoneStatus | Cellular and call state |
| MediaBrowser | Browse and search media content |
| MediaPlayback | Queue and playback status |
| Radio | Tuner control |
| GenericNotification | General notifications |
| WifiProjection | Wireless projection setup |
| VendorExtension | OEM/vendor-specific extensions |

---

## Versioning

The library carries two independent version numbers:

- **Library version** (e.g. `4.1.4`) — the `.so` version used for packaging and CMake, defined in `CMakeLists.txt`.
- **Protocol version** (`1.6`) — the AAP wire protocol version negotiated with the Android device, defined in `include/aasdk/Version.hpp`.

---

## License

GNU GPLv3

---

## Credits and acknowledgements

- **Michal Szwaj** ([f1x.studio](https://github.com/f1x-studio/aasdk)) — original aasdk library author (2018)
- **OpenCarDev / CrankShaft team** ([opencardev](https://github.com/opencardev)) — ongoing maintenance and the CrankShaft headunit project
- **milek7** ([github.com/Milek7](https://github.com/Milek7)) — reverse-engineering and documentation of the Android Auto Protocol 1.6, without which the AAP 1.6 protobuf definitions in this library would not exist. Research published at [milek7.pl/.stuff/galdocs/](https://milek7.pl/.stuff/galdocs/readme.md)
- **Simon Dean / CubeOne** — AAP 1.6 integration, CMake overhaul, Yocto support, and ongoing maintenance

---

*Android Auto is a registered trademark of Google Inc.*

### Used software

- [Boost libraries](http://www.boost.org/)
- [libusb](http://libusb.info/)
- [CMake](https://cmake.org/)
- [Protocol Buffers](https://developers.google.com/protocol-buffers/)
- [OpenSSL](https://www.openssl.org/)
- [Google Test](https://github.com/google/googletest)