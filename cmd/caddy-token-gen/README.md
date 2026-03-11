# caddy-token-gen

Tool to generate static tokens for use with the Caddy plugin

## install

```shell
go install github.com/loafoe/caddy-token/cmd/caddy-token-gen@latest
```

# usage

```shell
caddy-token-gen g -e client-test -r us-east -p fake -o fake
```

Append the output to your static token file.

# license

License is Apache 2.0
