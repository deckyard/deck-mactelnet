<!-- SPDX-License-Identifier: LGPL-3.0-only -->
<!-- SPDX-FileCopyrightText: Copyright (C) 2026 mplx <mplx@jennifer-lang.dev> -->

# @jennifer/mactelnet

A MikroTik™ MAC-Telnet™ client: a console to a RouterOS™ device by its MAC
address, with no IP configured on either side, as Winbox™'s "Neighbors" console
does. It is how a fresh or just-reset router gets its first address, before
you move on to the RouterOS API over IP (`@jennifer/mikrotik`). The full API
is on the [cheatsheet](cheatsheet.md).

## Conventions

Snippets assume this import:

```jennifer
import "@jennifer/mactelnet/" as mactelnet;
```

The trailing slash resolves to the entry module.

## A session

```jennifer
# "eth0" faces the router; its MAC is read from /sys/class/net/eth0/address
def s as mactelnet.Session init mactelnet.connect("eth0", "e4:8d:8c:11:22:33", "admin", "");
def banner as string init mactelnet.recv($s, 1000);

mactelnet.send($s, "/ip address add address=192.168.88.10/24 interface=ether1\r\n");
def out as string init mactelnet.recv($s, 1500);

mactelnet.close($s);
```

The console is the router's text CLI, not the API: send a command line ending
in `\r\n`, as you would type it, and read the echo and output with `recv`.
`recv` returns what has arrived, possibly `""`, and passes the CLI's ANSI
escapes through. It waits at most `timeoutMs`, even while output keeps coming;
call it again for the rest. `closed` tells whether the router ended the
session.

Output the router sends while you are not calling `recv` (during `send`, say)
is kept for the next `recv`, up to 1 Mi characters. Past that the call throws
kind `"limit"`; the packet is not acknowledged, so the router sends it again
after a `recv` has made room.

A blank password is valid; a factory-default router has `admin` with none.

## Login

The router picks the login method by the salt it sends:

| Salt | Method | RouterOS |
|---|---|---|
| 49 bytes | EC-SRP over Curve25519 (`crypto.mtwei*`) | 6.43 and later, all of v7 |
| 16 bytes | MD5: `0x00` + MD5(`0x00` + password + salt) | before 6.43 |

Neither sends the password itself, but an MD5 proof is enough to test
password guesses against offline, for anyone who captures it on the segment
or a host that answers in the router's place and offers the 16-byte salt. So
`connect` speaks EC-SRP only, and refuses a router offering MD5 with an
`Error` of kind `"mactelnet"` before the proof is sent.

To reach a router older than 6.43, opt in on a wire you trust, and upgrade the
router once you are in:

```jennifer
def o as mactelnet.Options init mactelnet.options("eth0", "e4:8d:8c:11:22:33", "admin", "");
$o.allowLegacyMd5 = true;
def s as mactelnet.Session init mactelnet.connectWith($o);
```

## The local interface

MAC-Telnet is link-local: the host and the router must share a Layer-2
segment. Packets go to the broadcast address on UDP port 20561 with both MACs
inside, so they reach a router that has no address yet.

`iface` stamps the packets with that interface's MAC, and the socket is bound
to the interface (`SO_BINDTODEVICE`) so the broadcast leaves through it. The
bind needs no privilege on Linux™ 5.7 and later; older kernels need
`CAP_NET_RAW`, and without it the socket stays unbound. With one network link
up that does not matter; with several, an unprivileged run on an old kernel
can send out the wrong one and time out.

RouterOS answers MAC-Telnet on every interface by default. A router with
`/tool mac-server` narrowed does not answer, and `connect` times out.

## Errors

A failed login throws an `Error` of kind `"mactelnet"` with the router's own
text; so do a refused MD5 login, an unknown local interface and a malformed
MAC address. A router
that does not answer within about three seconds of retransmits (a wrong MAC,
a mac-server that is off, another segment) is kind `"timeout"`. A socket
failure comes from `net` unchanged.

```jennifer
try {
    def s as mactelnet.Session init mactelnet.connect("eth0", "e4:8d:8c:11:22:33", "admin", "");
    mactelnet.close($s);
} catch (e) {
    if ($e.kind == "timeout") {
        io.printf("no answer: is the router on this segment?\n");
    } else {
        throw $e;
    }
}
```

## Runtime

Needs `net` and Linux (broadcast UDP, the MAC from sysfs), so it runs on the
default `jennifer` binary only.

MAC-Telnet is cleartext: the password proof is hashed, but every command and
its output can be read by any host on the segment. Use it to bootstrap a
router on a wire you trust, then switch to api-ssl over IP.

## Moving from the standard library module

Jennifer has bundled `mactelnet` (`modules/mactelnet.j`) since 0.25.0. The
module is deprecated from 0.26.0 and removed in 0.28.0. This deck has the same
types and functions; only the import changes:

```jennifer
import "mactelnet.j" as mactelnet;              # before
import "@jennifer/mactelnet/" as mactelnet;     # after: jvc add @jennifer/mactelnet
```

The deck does not read `JENNIFER_MACTELNET_TARGET`, the module's hook for its
own tests.

## Trademarks

MikroTik™ and RouterOS™ are trademarks of SIA "Mikrotīkls". Linux™ is a
trademark of Linus Torvalds. Other product and company names may be
trademarks of their respective owners. They are used only to identify the
products this deck works with. This deck is an independent project, not
affiliated with, sponsored or endorsed by SIA Mikrotikls or Linus Torvalds.
