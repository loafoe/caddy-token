# caddy-token

Caddy token based authentication. Supports static, signed and and JWT tokens

## Example config

```caddyfile
{
    order token first
}

:3000 {
    token {
        jwt {
            issuer https://dex.issuer.lan
            group admin
        }
    }
  
    reverse_proxy https://some.service.internal {
        header_up Host {http.reverse_proxy.upstream.hostport}
    }
}


```

## Development

Read [Extending Caddy](https://caddyserver.com/docs/extending-caddy) to get an overview
of what interfaces you need to implement.

# building

You first need to build a new caddy executable with this plugin. The easiest way is to do this with xcaddy.

Install xcaddy:

```shell
go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
```

After xcaddy installation you can build caddy with this plugin by executing:

```shell
xcaddy build v2.8.4 --with github.com/loafoe/caddy-token
```
# usage

TODO

# license

License is Apache 2.0
