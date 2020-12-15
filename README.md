[![Project Status: Active – The project has reached a stable, usable state and is being actively developed.](https://www.repostatus.org/badges/latest/active.svg)](https://www.repostatus.org/#active)
[![GitHub](https://img.shields.io/github/license/User65k/flash_rust_ws)](./LICENSE)
![GitHub Workflow Status](https://img.shields.io/github/workflow/status/User65k/flash_rust_ws/Rust)

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

# Optional: Change logging - See README for more
log.appenders.stdout = {kind = "console"}
log.root = {level = "info", appenders = ["stdout"]}

["example.com"]
ip = "127.0.0.1:1337"
#validate_server_name = true # Optional: Match Host header against this vHost
dir = "/var/www/" # Optional: A mount point must match if omitted
tls.host = [{key_file = "./4kRsa.pem", cert_file = "./localhost.crt"}] # Optional: use HTTPS

["example.com".docs] # /docs/* will not go to /var/www/ but to ./target/doc/
dir = "target/doc/"
index = ["index.html"]
# Optional: Set some headers if they were not present before
header = {Referrer-Policy = "strict-origin-when-cross-origin", Feature-Policy = "microphone 'none'; geolocation 'none'"}
follow_symlinks = true # Optional: follow symlinks
auth = {type = "Digest", realm = "test", userfile = ".htdigest"}

["example.com".php] # /php/* will go to php-cgi via FastCGI
dir = "/opt/php/"
index = ["index.php"]
fcgi.sock = "127.0.0.1:9000" # TCP
fcgi.exec = ["php"] # check that the file exists and ends in .php
# Optional: If we don't want so serve everything else,
# we can limit what will be served to:
serve = ["css", "js", "png", "jpeg", "jpg"]
# PHP does not follow the CGI/1.1 spec, it needs SCRIPT_FILENAME set
# to do so:
fcgi.script_filename = true
# Optional: Start the FCGI App from here
fcgi.bin.path = "/usr/bin/php-cgi7.4"
fcgi.bin.environment = {PHP_FCGI_CHILDREN = "16", PHP_FCGI_MAX_REQUESTS = "10000"}
fcgi.bin.copy_environment = ["PATH", "SHELL", "USER"]

["example.com".py] # /py/* will go to flup via FastCGI
dir = "/opt/py/"
fcgi.sock = "/tmp/py.sock" # Unix Socket
# we don't check if the file actually exists. This is up to Python


["example.com".php-fpm] # /php-fpm/* will go to php-cgi via FastCGI
fcgi.sock => "/var/run/php/php7.4-fpm.sock",
fcgi.script_filename = true

```
Place the config file in one of these places:

- `./config.toml`
- `/etc/defaults/config.toml`

# Goals
- Easy configuration and safe defaults
- Light Footprint
- Speed

# Functions
- [x] Virtual Hosts
- [x] "Mount Points" to serve files from
- [x] [FastCGI](https://github.com/User65k/async-fcgi)
- [x] HTTPS
  - [x] [rustls](https://github.com/ctz/rustls) (Fast)
    - [x] Cert per vHost / SNI
    - [x] Cert per Keytype (EC, ED, RSA)
    - [ ] ACME-TLS
  - [ ] [native-tls](https://github.com/sfackler/rust-native-tls) (Smaller binary - Once [rust-native-tls#105](https://github.com/sfackler/rust-native-tls/issues/105) / [rust-native-tls#163](https://github.com/sfackler/rust-native-tls/issues/163) is done)
- [x] HTTP2
- [ ] WebDAV
- [ ] Websocket
  - [ ] Reverse-Proxy
  - [ ] to normal Socket (SCGI Style)
- [x] Customizable Logging
  - [ ] to journald
  - [ ] to Windows Event Log?
- [ ] Security
  - [x] HTTP user auth: Digest - (MD5 because FireFox, but better that nothing)
  - [ ] DoS protection
    - [x] Don't be affected by Sloloris
    - [ ] limit connection count ?
    - [ ] rate ?
    - [ ] min speed ?
  - [x] no default files
  - [ ] no DAV without users
  - [x] no folder listings (except DAV)
  - [x] recomended http headers by default
  - [x] no path traversals :-)
  - [ ] only https ?
  - [ ] lets encrypt build in ?
  - [x] avoid BEAST and CRIME
  - [x] only follow symlinks if told so
- [ ] SCGI

# Logging

See [log4rs](https://docs.rs/log4rs/0.12.0/log4rs/) and its [patterns](https://docs.rs/log4rs/0.12.0/log4rs/encode/pattern/index.html).
It defaults to log on STDERR:

- `flash_rust_ws::config` Info (Configuration parsing)
- `flash_rust_ws::dispatch` Warn (Request resolving)
- `flash_rust_ws` Warn (This server)
- `hyper` Warn (Low level HTTP server)
- `async_fcgi` Warn (FastCGI)
- `flash_rust_ws::transport::tls` Warn (TLS)
- `rustls` Warn (Low level TLS)

## Logging Example

- Log all requests to `./requests.log` (Level info for `flash_rust_ws::dispatch`)
- Log everything else as usual

```toml
# Log warnings+ to STDERR (default)
log.appenders.stderr = {kind = "console", target="stderr", encoder={pattern = "{d(%Y-%m-%d %H:%M:%S %Z)(utc)} {h({l})} {t} - {m}{n}"}}
log.root = {level = "warn", appenders = ["stderr"]}
# Log info+ of class "flash_rust_ws::dispatch" to "./requests.log"
log.appenders.requests = {kind = "file", path = "./requests.log", append=true, encoder={pattern = "{d} {m}{n}"}}
log.loggers."flash_rust_ws::dispatch" = {level = "info",appenders = ["requests"],additive = false}
```
or
```toml
# Log warnings+ to STDERR (default)
[log.appenders.stderr]  # create an appender named "stderr"
kind = "console"  # ... that logs to the console
target = "stderr"  # ... on stderr (not out)
encoder = {pattern = "{d(%Y-%m-%d %H:%M:%S %Z)(utc)} {h({l})} {t} - {m}{n}"}

[log.root]
level = "warn"
appenders = ["stderr"]  # use the appender from above

# Log info+ of class "flash_rust_ws::dispatch" to "./requests.log"
[log.appenders.requests]  # create an appender named "requests"
kind = "file"  # ... that logs to a file
path = "./requests.log"
append = true  # do not overwrite the file
encoder = {pattern = "{d} {m}{n}"}

[log.loggers."flash_rust_ws::dispatch"]  # create an addtional logger for the class "flash_rust_ws::dispatch"
level = "info"
appenders = ["requests"]
additive = false  # do NOT also use the root logger
```