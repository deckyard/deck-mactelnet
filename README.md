# @deckyard/mactelnet

[![test](https://github.com/deckyard/deck-mactelnet/actions/workflows/test.yml/badge.svg)](https://github.com/deckyard/deck-mactelnet/actions/workflows/test.yml)
[![Documentation](https://img.shields.io/badge/docs-github%20pages-blue)](https://deckyard.github.io/deck-mactelnet/)
[![release](https://img.shields.io/github/v/release/deckyard/deck-mactelnet)](https://github.com/deckyard/deck-mactelnet/releases/latest)

A [Jennifer](https://jennifer-lang.dev/) deck that opens a MikroTik™ MAC-Telnet™
console: a RouterOS™ command line reached by the router's MAC address, with no
IP configured on either side. It is the way to give a fresh or just-reset
router its first address.

It was Jennifer's bundled `mactelnet.j` module until 0.27; the surface is the
same, so moving over changes only the import:

```jennifer
import "@deckyard/mactelnet/" as mactelnet;   # was: import "mactelnet.j" as mactelnet;
```

Up to 0.2.0 this deck was `@jennifer/mactelnet`. To switch, change the `[decks]`
entry to `"@deckyard/mactelnet" = "^0.3.0"` and the imports to `"@deckyard/mactelnet/"`.

**[Documentation](https://deckyard.github.io/deck-mactelnet/)**

## Install

```sh
jvc add @deckyard/mactelnet
```

This vendors the deck to `vendor/<scope>/mactelnet/`. Without `jvc`, unpack the
`src/` subtree of a release archive (`<scope>-mactelnet-<version>.tar.gz`) there.

## Usage

```jennifer
import "@deckyard/mactelnet/" as mactelnet;

def s as mactelnet.Session init mactelnet.connect("eth0", "e4:8d:8c:11:22:33", "admin", "");
mactelnet.send($s, "/ip address add address=192.168.88.10/24 interface=ether1\r\n");
io.printf("%s", mactelnet.recv($s, 1500));
mactelnet.close($s);
```

## Requirements

Jennifer 0.27.0 or newer, the default `jennifer` binary (`net`) on Linux™, not
`jennifer-tiny`, and the router on the same Layer-2 segment.

## Development

```sh
tools/check-all.sh                    # the full gate, as CI runs it
jennifer test src/mactelnet_test.j    # the test overlay
tools/check-docs.sh                   # docs against the code
tools/pack.sh dist                    # build the release archive
```

## Licence

LGPL-3.0-only, see [LICENSE](LICENSE). Copyright (C) 2026 mplx &lt;mplx@jennifer-lang.dev&gt;.

`tools/check-headers.sh` checks every source file's SPDX header against
`deck.toml`.

## Trademarks

MikroTik™ and RouterOS™ are trademarks of SIA "Mikrotīkls". Linux™ is a
trademark of Linus Torvalds. Other product and company names may be
trademarks of their respective owners. They are used only to identify the
products this deck works with. This deck is an independent project, not
affiliated with, sponsored or endorsed by SIA Mikrotikls or Linus Torvalds.
