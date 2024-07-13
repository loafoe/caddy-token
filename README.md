# caddy-token

Caddy token based authentication. Supports static tokens and JWT ID Tokens

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