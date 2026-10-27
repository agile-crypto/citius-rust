# Template catalog

`standard_algorithms.json` is the catalog compiled into the library, used
when `agc_ctx_config.catalog_path` is NULL.

It is citius-server's catalog at the same commit that citius-c-api's pinned
API descriptor (`conformance/api_descriptor.binpb`) was built from, so the
catalog and the generated types describe the same API version. Later
catalogs use fields this descriptor does not have.

| | |
|---|---|
| Source repo | `citius-server` |
| Source commit | `476f9dd1ef20dedbbe7483474cc71acf41637445` |
| Source path | `proto/standard_algorithms.json` |
| Catalog version | 0.1.0 (72 templates) |
| `sha256` | `3df8d0fd1ef6513e094c0bc7cc6fd3bc52971851504dedeb7f21cc6eeb324b12` |

Bump it together with the descriptor, as a deliberate commit:

```sh
git -C ../citius-server show <commit>:proto/standard_algorithms.json > catalog/standard_algorithms.json
```
