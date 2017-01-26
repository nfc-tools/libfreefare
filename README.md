# Introduction

[![Join the chat at https://gitter.im/nfc-tools/libfreefare](https://badges.gitter.im/nfc-tools/libfreefare.svg)](https://gitter.im/nfc-tools/libfreefare?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

The _libfreefare_ project provides a convenient API for MIFARE card manipulations.

It is part of the _nfc-tools_, you can find more info on them on the [nfc-tools wiki](http://nfc-tools.org/).

If you are new to _libfreefare_ or the _nfc-tools_, you should collect useful information on the [project website](http://nfc-tools.org/) and the [dedicated forums](http://www.libnfc.org/community).

# Feature matrix
## Tags
| Tag                 | Status        |
|:--------------------|:--------------|
| FeliCa Lite         | Supported     |
| MIFARE Classic 1k   | Supported     |
| MIFARE Classic 4k   | Supported     |
| MIFARE DESFire 2k   | Supported     |
| MIFARE DESFire 4k   | Supported     |
| MIFARE DESFire 8k   | Supported     |
| MIFARE DESFire EV1  | Supported     |
| MIFARE Mini         | Supported     |
| MIFARE Plus S 2k    | Not supported |
| MIFARE Plus S 4k    | Not supported |
| MIFARE Plus X 2k    | Not supported |
| MIFARE Plus X 4k    | Not supported |
| MIFARE Ultralight   | Supported     |
| MIFARE Ultralight C | Supported     |

## Specifications
| Specification                         | Status    |
|:--------------------------------------|:----------|
| Mifare Application Directory (MAD) v1 | Supported |
| Mifare Application Directory (MAD) v2 | Supported |
| Mifare Application Directory (MAD) v3 | Supported (part of Mifare DESFire support) |

# Installation

## For *NIX systems

You can use released version (see **Download** section) or development version:

First, ensure all dependencies are installed:
* [libnfc](https://github.com/nfc-tools/libnfc);
* git;
* Autotools (autoconf, automake, libtool);
* OpenSSL development package.
```
apt-get install autoconf automake git libtool libssl-dev pkg-config
```

Clone this repository:
```
git clone https://github.com/nfc-tools/libfreefare.git
cd libfreefare
```

Before compiling, remember to run:
```
autoreconf -vis
```

You can now compile **libfreefare** the usual autotools way:
```
./configure --prefix=/usr
make
sudo make install
```
## For Windows Systems

### Requirements

* cmake
* make
* mingw{32,64}-gcc

### Building

    mingw64-cmake -DLIBNFC_INCLUDE_DIRS=/path/to/libnfc-source/include  -DLIBNFC_LIBRARIES=/path/to/libnfc.dll
    mingw64-make

# Debug
In order to debug using gdb, you should tune the CFLAGS:
```
CFLAGS="-O0 -ggdb" ./configure --prefix=/usr
make clean all
```

It is then possible to debug examples using this kind of command from the root of the repository:
```
./libtool --mode=execute gdb examples/mifare-classic-write-ndef
```

If you are only interested in viewing transfert traces between the PCD and the PICC, simply use the `--enable-debug` configure flag:
```
./configure --enable-debug
make clean all
```
