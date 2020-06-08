A Webserver written in Rust.
Build on the speedy [Hyper](https://hyper.rs/).

# Usage

## Installation

[Install cargo](https://www.rust-lang.org/tools/install) and then:
`cargo install --git https://github.com/User65k/flash_rust_ws.git`


## Example Config
```toml
pidfile  = "/var/run/frws.pid" # Optional: Write PID to this file
# Optional: Change user after binding
#user = "www-data"
#group = "www-data"

["example.com"]
ip = "127.0.0.1:1337"
#validate_server_name = true # Optional: Match Host header against this vHost
dir = "/var/www/"
["example.com".docs] # /docs will not go to /var/www/ but to ./target/doc/
dir = "target/doc/"
index = ["index.html"]
```
Place the config file in one of these places:

- `./config.toml`
- `/etc/defaults/config.toml`

# Goals
- Easy configuration and safe defaults
- Light Footprint
- Speed

# Functions
- [ ] Websocket
  - [ ] Reverse-Proxy
  - [ ] to normal Socket (SCGI Style)
- [x] Virtual Hosts
- [x] "Mount Points" to serve files from
- [ ] SCGI
- [x] FCGI
- [ ] WebDAV
- [ ] HTTPS
  - [ ] rustls (Fast)
  - [ ] native-tls (Smaller binary)
- [ ] Security
  - [ ] DoS protection
    - [ ] limit connection count ?
    - [ ] rate ?
    - [ ] min speed ?
  - [x] no default files
  - [ ] no DAV without users
  - [x] no folder listings (except DAV)
  - [ ] recomended http headers by default
  - [x] no path traversals :-)
  - [ ] users with blowfish
  - [ ] http digest auth ( https://developer.mozilla.org/en-US/docs/Web/HTTP/Authentication )
  - [ ] only https ?
  - [ ] lets encrypt build in ?
  - [x] avoid BEAST and CRIME