# RedProxy.Server 

This application is a cross-platform proxy server supporting socks4/socks4a and socks5 protocols, written in C++ using the [boost.asio](https://github.com/boostorg/asio) library.

## Features

- SOCKS4 Protocol
  - [x] `socks4a` Supports
  - [x] `USER-ID` Authentication
  - Commands
    - [x] `CONNECT`
    - [x] `BIND`
   
- SOCKS5 Protocol
  - [x] IPv6 Supports
  - Authentication
    - [x] `NO-AUTH`
    - [x] `USERNAME-PASSWORD`
  - Commands
    - [x] `CONNECT`
    - [x] `BIND`
    - [x] `UDP-ASSOCIATE`

## Build & Run

```console
$> cmake -S . -B Build
$> cmake --build Build
```

## Usage
By default, the application can be supplied without a configuration file, and will use the default values that will be described below. 
If you need to configure the application with parameters other than the usual ones, you need to create a file `settings.ini` next to the executable file of the application.
<br>
This configuration file should contain several sections with the following parameters:

#### SOCKS4 Section

| Key             | Value      | Description                                                                                  | 
|-----------------|------------|----------------------------------------------------------------------------------------------|
| enable          | bool       | Enable socks4 server. `true` by default.                                                     | 
| enable_connect  | bool       | Enable `CONNECT` command. `true` by default.                                                 |
| enable_bind     | bool       | Enable `BIND` command. `true` by default.                                                    |
| user_id         | string     | The value of authorization. If it is empty, authorization is not required. Empty by default. |
| address         | string     | Server address. By default `127.0.0.1`                                                       |
| port            | uint16_t   | Server port. By default `1080`.                                                              |

#### SOCKS5 Section

| Key             | Value      | Description                                                                                  | 
|-----------------|------------|----------------------------------------------------------------------------------------------|
| enable          | bool       | Enable socks4 server. `true` by default.                                                     | 
| enable_connect  | bool       | Enable `CONNECT` command. `true` by default.                                                 |
| enable_bind     | bool       | Enable `BIND` command. `true` by default.                                                    |
| enable_udp      | bool       | Enable `UDP-ASSOCIATE` command. `true` by default.                                           |
| username        | string     | The value of authorization. If it is empty, authorization is not required. Empty by default. |
| password        | string     | The value of authorization. If it is empty, authorization is not required. Empty by default. |
| address         | string     | Server address. By default `127.0.0.1`                                                       |
| port            | uint16_t   | Server port. By default `1081`.                                                              |

### `settings.ini` example:
```ini
[socks4]
enable=true
enable_connect=true
enable_bind=true
user_id=test
address=127.0.0.1
port=1080

[socks5]
enable=true
enable_connect=true
enable_bind=true
enable_udp=true
username=test
password=test
address=127.0.0.1
port=1081
```




