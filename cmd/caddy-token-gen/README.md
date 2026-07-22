# caddy-token-gen

CLI tool to generate and verify signed API keys (versions 2 & 3) and static tokens (version 1) for use with the [caddy-token](https://github.com/loafoe/caddy-token) Caddy plugin.

## Install

```shell
go install github.com/loafoe/caddy-token/cmd/caddy-token-gen@latest
```

## Usage

### Generate Signed API Key

```shell
caddy-token-gen g -v 2 -k "your-secret-signing-key" -o my-org -r us-east -p my-project -e prod --ttl 720h
```

Pass the generated token in requests using the `X-Api-Key` header:

```shell
curl -H "X-Api-Key: lst_..." https://your-caddy-server.com/
```

### Verify API Key

```shell
caddy-token-gen verify -k "your-secret-signing-key" -t "lst_..."
```

### Static Tokens (Version 1)

For static token file authentication, generate a version 1 token and append it to your static token file:

```shell
caddy-token-gen g -v 1 -o my-org -r us-east -p my-project -e prod
```

## License

Apache 2.0
