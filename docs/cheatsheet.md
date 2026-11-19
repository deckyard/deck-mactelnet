<!-- SPDX-License-Identifier: LGPL-3.0-only -->
<!-- SPDX-FileCopyrightText: Copyright (C) 2026 mplx <mplx@jennifer-lang.dev> -->

# mactelnet cheatsheet

Every export of `@jennifer/mactelnet`. Background is in
[the introduction](index.md).

```jennifer
import "@jennifer/mactelnet/" as mactelnet;
```

A failed or refused login, an unknown local interface and a malformed MAC
address throw an `Error` of kind `"mactelnet"`. A router that does not answer
is kind `"timeout"`, console output left unread past 1 Mi characters
(`MAX_CONSOLE_CHARS`) kind `"limit"`; a socket failure comes from `net`
unchanged.

## Types

### `Options`

| Field | Meaning |
|---|---|
| `iface as string` | local network interface |
| `mac as string` | router MAC address |
| `user as string` | login user |
| `password as string` | login password, `""` for none |
| `allowLegacyMd5 as bool` | accept the MD5 login of RouterOS before 6.43; default `false` |

### `Session`

| Field | Meaning |
|---|---|
| `sock as net.UDPSocket` | the broadcast socket |
| `state as kv.Store` | send and receive counters, buffered output |
| `srcmac as bytes` | local interface MAC, 6 bytes |
| `dstmac as bytes` | router MAC, 6 bytes |
| `seskey as int` | 16-bit session key |

## Sessions

| Function | Returns | Notes |
|---|---|---|
| `mactelnet.connect(iface, mac, user, password)` | `Session` | session start and EC-SRP login; a router offering only MD5 is refused |
| `mactelnet.options(iface, mac, user, password)` | `Options` | what `connect` uses, `allowLegacyMd5` off |
| `mactelnet.connectWith(opts)` | `Session` | `connect` with options; MD5 only with `allowLegacyMd5` |
| `mactelnet.send(s, text)` | | console input; end a command with `"\r\n"` |
| `mactelnet.recv(s, timeoutMs)` | `string` | output so far, waiting at most `timeoutMs` |
| `mactelnet.closed(s)` | `bool` | whether the router ended the session |
| `mactelnet.close(s)` | | end the session, release the socket |

## MAC addresses

| Function | Returns | Notes |
|---|---|---|
| `mactelnet.parseMac(s)` | `bytes` | `aa:bb:cc:dd:ee:ff`, `-` separators or none |
| `mactelnet.formatMac(b)` | `string` | lower case, `:` separated |
