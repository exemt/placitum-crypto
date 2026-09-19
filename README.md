# Placitum crypto

English · [Русский](README.ru.md)

Holder of the private installation key, next to the controller. It does one thing: on the
controller's request it opens the envelope of a stored object (a certificate, a private key, a
chain or a CRL) and returns metadata, never the plaintext.

The controller must never see the plaintext of secrets uploaded through the panel. The operator
still needs to see the SANs and validity of a certificate and to know that the key matches it.
That takes the private key, so the check runs here.

```
panel ──► controller ──► crypto ── fetches the ciphertext from the controller itself
                           │       (GET /api/<scope>/store/<uuid>/blob)
                           └──►    metadata: SANs, validity, key match
```

The controller passes only the scope and object UUIDs. The plaintext never leaves the process.

## Build and run

```sh
docker build -t placitum/crypto .
docker run --rm -p 8093:8093 \
  -v /path/contour.key:/run/secrets/waf_node_key:ro \
  -e WAF_NODE_KEY=/run/secrets/waf_node_key \
  -e WAF_CONTROLLER_URL=http://controller:8080 \
  placitum/crypto
```

What it needs and all settings are in [INSTALL.md](INSTALL.md).

## API

| Request | Response |
| --- | --- |
| `POST /v1/certificates/metadata`: `scope`, `cert_store_id`, optional `key_store_id` and `chain_store_id` | `sans`, `not_before`, `not_after`, `fingerprint`, `subject`, `issuer`, `serial`, `is_ca` |
| `POST /v1/crl/metadata`: `scope`, `crl_store_id` | `issuer`, `this_update`, `next_update`, `revoked` (a count) |
| `GET /healthz` | `200`; the key is not checked |

A trusted mTLS root comes without `key_store_id`: there is no private half to compare with. `is_ca`
comes from BasicConstraints of the certificate itself, so the controller can reject a leaf
certificate uploaded as a root.

Errors are JSON with an `error` code:

| Status | `error` | When |
| --- | --- | --- |
| `400` | `invalid_json`, `invalid_uuid` | the body is not JSON, or an id is not a UUID |
| `404` | `store_object_not_found` | the controller has no such object |
| `422` | `undecryptable` | the envelope does not open with the current key |
| `422` | `invalid_certificate`, `invalid_crl` | the decrypted object is not a valid certificate or CRL |
| `422` | `key_mismatch` | the key does not match the certificate |
| `502` | `controller_unreachable` | the controller could not be reached |
| `503` | `key_unavailable` | the process was started without a key |

## Good to know

- **The installation key is the same one node agents use**: the private half, as a file readable
  only by the process. The controller holds the public half.
- **One envelope format** for everyone who writes or reads it: version, big-endian length of the
  wrapped key, RSA-OAEP-SHA256, then AES-256-GCM.
- **No database and no state**: a restart loses nothing.
- **Not checked here**: the chain against system trust and the CRL signature. The controller
  matches the CRL issuer with the root.

## License

[Apache License 2.0](LICENSE); the attribution notice is in [NOTICE](NOTICE). This repository is
part of the Placitum open core. The inspectors are licensed separately: each inspector repository
carries the Placitum License Agreement. Releases made before this change came under the Placitum
License Agreement 1.1.
