# internal-auth-utils (DEMONSTRATION PACKAGE)

This is **not** a real library. It is the "attacker" side of the dependency
confusion lab.

- **Name**: `internal-auth-utils` — chosen to look like a private corporate
  library that a developer might depend on.
- **Version**: `99.0.0` — absurdly high on purpose, so it beats any real
  internal version (e.g. `1.4.2`) during dependency resolution. This *is* the
  dependency-confusion trick: the resolver picks the highest version it can see
  across all configured indexes.
- **Payload**: a benign, local-only telemetry hook (`_telemetry.py`) that
  collects non-sensitive metadata and POSTs it to `http://127.0.0.1:8888/collect`.
  It runs at **build time**, at **install time** (via a custom `install`
  command in `setup.py`), and on **import**.

Build an sdist (so the hooks run on install):

```bash
python -m build --sdist .      # produces dist/internal-auth-utils-99.0.0.tar.gz
```

Then upload it to the **local** registry only (see ../../scripts/publish_package.sh).
