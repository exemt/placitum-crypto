# Installation

English · [Русский](INSTALL.ru.md)

The service runs next to the controller and is needed only when certificates and keys are uploaded
through the panel. Usually `placitum-core` installs it; this page lists what it needs and how to
check that it works.

## What it needs

| Component | Required | Why |
| --- | --- | --- |
| Controller | yes | the service fetches object ciphertext from it and answers it with metadata |
| Private installation key | yes | it opens the envelopes; mount it as a file, not a variable |
| NATS | no | only for its own log and the live log level |

The service has no database, volume or state: a restart loses nothing.

## Settings

| Variable | Default | Purpose |
| --- | --- | --- |
| `WAF_CRYPTO_HTTP` | `:8093` | HTTP API address |
| `WAF_NODE_KEY` | empty | path to the private installation key (PKCS#8 PEM). Without it the service starts, but metadata requests get `503 key_unavailable`; a key that cannot be read stops the start |
| `WAF_CONTROLLER_URL` | — | required; where to fetch ciphertext, for example `http://controller:8080` |
| `WAF_NATS_URL` | empty | bus for the log; without it the log stays on stdout |
| `WAF_CRYPTO_LOG` | `info` | log level |
| `WAF_CRYPTO_REQUEST_TIMEOUT` | `5s` | limit for a request to the controller |

Mount the key as a file readable only by the process: environment variables are visible to other
processes on the machine and end up in dumps, a file does not.

## Docker Compose

```yaml
services:
  crypto:
    image: placitum/crypto
    environment:
      WAF_CRYPTO_HTTP: ":8093"
      WAF_NODE_KEY: /run/secrets/waf_node_key
      WAF_CONTROLLER_URL: http://controller:8080
      WAF_NATS_URL: nats://nats:4222
    secrets: [waf_node_key]

secrets:
  waf_node_key:
    file: ./secrets/contour.key
```

Do not publish `:8093`: the controller talks to the service, browsers do not.

## Checking

```sh
curl -fsS http://127.0.0.1:8093/healthz
```

Then upload a certificate with its key in the panel and open its card. If the card shows SANs and
validity and the controller does not complain, the whole path panel → controller → crypto →
metadata works.

`undecryptable` with the right key means the envelope format of the panel encryptor and of this
reader have drifted apart. Envelopes are written in more than one place, so fix every
implementation at once.

## Pitfalls

- **One installation key per installation.** Node agents get the same file, the controller gets the
  public half. Reissuing the key makes every previously uploaded secret unreadable.
- **The service does not take part in nginx rollout.** It holds the same key as the agent but never
  applies configuration or talks to nodes.
- **The plaintext is never returned**, neither to the controller nor to the log.
