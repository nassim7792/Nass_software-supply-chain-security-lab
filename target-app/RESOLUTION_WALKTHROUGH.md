# What happens during `uv sync` — step by step

This is the heart of the lab. Read it alongside `pyproject.toml`.

## The mental model: how resolvers pick a version

A dependency resolver must answer: *"For the name `internal-auth-utils`, which
distribution do I install?"* It does this by:

1. Collecting the **set of configured indexes** (here: the private index at
   `127.0.0.1:8080`, plus PyPI as an extra).
2. Asking each index for the **available versions** of the name.
3. Choosing one version according to its **index strategy**:
   - `first-index` (uv's default, safer): use only the **first index** that
     lists the name. If your private index has it, PyPI is never consulted.
   - `unsafe-best-match` (what this app sets, pip-like): merge versions from
     **all** indexes and pick the **highest** compatible one.

Dependency confusion lives in step 3. If the resolver merges indexes and picks
the highest version, an attacker only needs to publish a **higher version under
the same name** on *any* index the resolver trusts.

## The lab's rendering of the attack

In the real 2021 attack the direction was:

```
private index:  internal-auth-utils == 1.4.2   (the real library)
public PyPI:    internal-auth-utils == 99.0.0   (attacker's impostor)  ← wins
```

We cannot (and must not) publish anything to public PyPI, so the lab renders
the same mechanic locally:

```
local registry (:8080):  internal-auth-utils == 99.0.0  (impostor)  ← wins
public PyPI:             internal-auth-utils  (absent)
```

Either way, the resolver installs **99.0.0**, the impostor, because it is the
highest version it can see across trusted indexes.

## Trace of `uv sync`

1. `uv` reads `pyproject.toml`, sees the dependency `internal-auth-utils`.
2. It queries the primary index (`:8080/simple/internal-auth-utils/`) and the
   extra index (PyPI). The local index returns version **99.0.0**.
3. Because `index-strategy = "unsafe-best-match"`, uv selects **99.0.0**.
4. uv downloads the **sdist** `internal-auth-utils-99.0.0.tar.gz`.
5. To install it, uv builds it: it runs the package's build backend, which
   executes `setup.py`. The custom `build_py` command fires the telemetry hook
   (**stage = "build"**).
6. uv installs the built wheel. When installed from source, the custom
   `install` command also fires (**stage = "post-install"**).
7. Later, when `main.py` runs `import internal_auth_utils`, the import-time hook
   fires (**stage = "import"**).

Each of those stages sends a benign metadata beacon to the localhost monitor at
`:8888`, so you see three events on the timeline for a single careless
dependency line.

## Why this is so impactful

The developer never typed a malicious name, never clicked anything, never saw a
warning. A single line in `pyproject.toml` plus a permissive index config was
enough to run attacker code on the build machine, the CI runner, and every
developer laptop that ran `uv sync`.
