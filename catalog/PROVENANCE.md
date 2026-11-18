# Template catalog

`standard_algorithms.json` is the catalog compiled into the library, used
when `agc_ctx_config.catalog_path` is NULL.

It is the catalog of the API release citius-c-api's pinned descriptor
(`conformance/api_descriptor.binpb`) was built from, so the catalog and
the generated types describe the same API version. Later
catalogs use fields this descriptor does not have.

| | |
|---|---|
| Source repo | `agile-crypto/api` |
| Source tag | `v0.3.0` (`2eb364a69b5a7ba41d3770af35248f452930a787`) |
| Source path | `proto/standard_algorithms.json` |
| Catalog version | 0.2.1 (72 templates) |
| `sha256` | `9a46a0ecfc9104473405bc88b1c3ebd9faef5b451b9e5064930b429fe332b69e` |

It is byte-identical to the catalog citius-server ships (`proto/standard_algorithms.json`).

Bump it together with the descriptor, as a deliberate commit:

```sh
git -C ../citius-server show <commit>:proto/standard_algorithms.json > catalog/standard_algorithms.json
```
