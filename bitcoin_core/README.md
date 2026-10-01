# Code derived from Bitcoin Core

This directory contains code taken from, or derived from,
[Bitcoin Core](https://github.com/bitcoin/bitcoin), which is distributed under
the MIT software license (see the copyright notices in the individual files).

The layout of this directory matches that of Bitcoin Core's `src/` directory: a
file `bitcoin_core/<path>` corresponds to `src/<path>` in Bitcoin Core. For
example, `bitcoin_core/netbase.h` corresponds to `src/netbase.h`, and
`bitcoin_core/compat/compat.h` to `src/compat/compat.h`. This directory is in
the include path, so these files can be included the same way as in Bitcoin
Core.

Most files are stripped-down versions of their Bitcoin Core counterparts,
containing only what this project needs, and some have been adapted to fit it.
Some derive from much older versions of Bitcoin Core than others, and may no
longer have a direct counterpart there (for example `util.h` and `util.cpp`).

Code specific to this project, including the P2P client logic used by the
crawler (in `bitcoin.cpp`), lives outside this directory.
