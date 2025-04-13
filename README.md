# Caddy PostgreSQL SSL Wrapper

A Caddy listener wrapper module that enables PostgreSQL SSL handshake support. This module allows Caddy to properly handle PostgreSQL's custom SSL handshake protocol, making it possible to terminate PostgreSQL SSL connections at Caddy.

## Overview

PostgreSQL uses a custom SSL handshake protocol that differs from standard TLS handshakes. When a PostgreSQL client initiates an SSL connection, it first sends a special SSL request message (StartTLS). The server must respond with a single byte 'S' to indicate SSL support before proceeding with the actual TLS handshake.

This module implements the necessary protocol handling to make PostgreSQL SSL connections work seamlessly with Caddy's TLS termination capabilities.

## Features

- Detects PostgreSQL SSL handshake requests
- Handles PostgreSQL's custom StartTLS protocol
- Seamlessly integrates with Caddy's TLS stack
- Zero-copy implementation for optimal performance
- IP-based access control support
- Configurable connection timeout

## Installation

To use this module, you need to build Caddy with both this module and the [caddy-l4](https://github.com/mholt/caddy-l4) module. Use xcaddy to build a custom Caddy binary:

```bash
xcaddy build \
    --with github.com/mholt/caddy-l4 \
    --with github.com/CloudPassenger/caddy-pgssl-wrap
```

## Configuration

The module is designed to work with the caddy-l4 module. Here's an example Caddyfile configuration that sets up PostgreSQL SSL termination:

```caddy
{
    servers :443 {
        listener_wrappers {
            http_redirect
            postgres_ssl {
                # Optional: timeout for handshake detection (default: 3s)
                timeout 3s
                # Optional: allowed client IPs
                allow 10.0.0.0/24 192.168.1.100
                # Optional: denied client IPs
                deny 172.16.0.0/16
            }
            layer4 {
                @tls-pg tls sni pg.example.com
                route @tls-pg {
                    tls {
                        connection_policy {
                            alpn postgresql
                        }
                    }
                    proxy postgres:5432
                }
            }
        }
    }
}
```

### Module Options

- `timeout`: Duration to wait for the PostgreSQL SSL handshake detection (default: 3s)
- `allow`: List of IP addresses or CIDR ranges that are allowed to connect
- `deny`: List of IP addresses or CIDR ranges that are denied from connecting

If a connection is denied or not allowed, it will be passed to the next listener wrapper in the chain, allowing other Caddy modules to handle it.

## How It Works

1. When a connection is received, the wrapper checks if it matches the configured IP allow/deny rules
2. If allowed, it attempts to detect the PostgreSQL SSL handshake request
3. If a PostgreSQL SSL request is detected, the wrapper responds with the appropriate 'S' byte
4. The connection is then passed to Caddy's TLS stack for standard TLS termination
5. If the connection is not a PostgreSQL SSL request, it's passed through unmodified

## Requirements

- Caddy v2
- [caddy-l4](https://github.com/mholt/caddy-l4) module

## References

- [Postgres filter: implement Postgres SSL termination and monitoring](https://github.com/envoyproxy/envoy/issues/10942)
- [Implement of Traefik V3 Postgres filter](https://github.com/traefik/traefik/blob/master/pkg/server/router/tcp/postgres.go)

## License

This project is licensed under the Apache License 2.0 - see the LICENSE file for details.