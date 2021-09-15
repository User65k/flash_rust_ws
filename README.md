[![Project Status: Active – The project has reached a stable, usable state and is being actively developed.](https://www.repostatus.org/badges/latest/active.svg)](https://www.repostatus.org/#active)
[![GitHub](https://img.shields.io/github/license/User65k/flash_rust_ws)](./LICENSE)
![GitHub Workflow Status](https://img.shields.io/github/workflow/status/User65k/flash_rust_ws/Rust)

A Webserver written in Rust.
Build on the speedy [Hyper](https://hyper.rs/).

# Usage

## Installation

[Install cargo](https://www.rust-lang.org/tools/install) and then:
`cargo install --git https://github.com/User65k/flash_rust_ws.git`

## Running

Create a config file and execute the binary :relaxed:

See the [Wiki](https://github.com/User65k/flash_rust_ws/wiki) for some help with the config file.

You will need at least a single [Host](https://github.com/User65k/flash_rust_ws/wiki/virtual-host) containing a [Mount Path](https://github.com/User65k/flash_rust_ws/wiki/mount-path).

Minimal Example:

```toml
["example.com"]
ip = "127.0.0.1:80"
dir = "/var/www/"
```

Let's Encrypt Example:
```toml
["example.com"]
ip = "[::]:443"
validate_server_name = true
dir = "/var/www/"
tls.host.ACME = {uri="https://acme-staging-v02.api.letsencrypt.org/directory",cache_dir=".",contact=["mailto:admin@example.com"]}
```

# Goals
- Easy configuration and safe defaults
- Light Footprint
- Speed

# Functions
- [x] [Virtual Hosts](https://github.com/User65k/flash_rust_ws/wiki/virtual-host)
- [x] ["Mount Points"](https://github.com/User65k/flash_rust_ws/wiki/mount-path) to serve files from
- [x] [FastCGI](https://github.com/User65k/flash_rust_ws/wiki/FCGI)
- [x] [HTTPS](https://github.com/User65k/flash_rust_ws/wiki/TLS)
  - [x] Cert per vHost / SNI
  - [x] Cert per Keytype (EC, ED, RSA)
  - [x] ACME-TLS
- [x] HTTP2
- [x] [WebDAV](https://github.com/User65k/flash_rust_ws/wiki/webdav)
- [ ] Reverse-Proxy
- [x] [Websocket](https://github.com/User65k/flash_rust_ws/wiki/websocket)
- [x] Customizable [Logging](https://github.com/User65k/flash_rust_ws/wiki/logging)
  - [x] to [journald](https://github.com/User65k/flash_rust_ws/wiki/systemd#journal)
  - [ ] to Windows Event Log?
- [ ] Security
  - [x] [HTTP user auth](https://github.com/User65k/flash_rust_ws/wiki/authentication): Digest - (MD5 because FireFox, but better that nothing)
  - [x] [Systemd Socket Activation](https://github.com/User65k/flash_rust_ws/wiki/systemd#socket-activation)
  - [ ] DoS protection
    - [x] Don't be affected by Sloloris
    - [ ] limit connection count ?
    - [ ] rate ?
    - [ ] min speed ?
  - [x] no default files
  - [ ] no DAV without users?
  - [x] no folder listings (except DAV)
  - [x] recomended http headers by default
  - [x] no path traversals :-)
  - [x] only use filters based on allowed values
  - [ ] only https ?
  - [x] avoid BEAST and CRIME
  - [x] only follow symlinks if told so
- [ ] SCGI

