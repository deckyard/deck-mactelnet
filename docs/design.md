<!-- SPDX-License-Identifier: LGPL-3.0-only -->
<!-- SPDX-FileCopyrightText: Copyright (C) 2026 mplx <mplx@jennifer-lang.dev> -->

# Design

## Scope

The deck is a MAC-Telnet client: session start, login (MD5 or EC-SRP), and a
console session over broadcast UDP to a router identified by MAC address. It
exists to reach a router that has no IP address yet.

It leaves out:

- **A terminal.** `send` and `recv` move text; there is no terminal emulation,
  no window-size updates after login and no ANSI parsing.
- **The server side** and MAC-Telnet discovery (MNDP). The caller knows the
  router's MAC, from its label or a neighbour list.
- **Anything beyond bootstrap.** Configuration over IP belongs to the RouterOS
  API (`@jennifer/mikrotik`), which has TLS.

## Decisions

- **A deck, not a bundled module.** A client for one vendor's protocol belongs
  in the deck ecosystem. The deck is one of the bundled modules that
  `jennifer` moves out (M30.1 in its milestones) and keeps the module's
  surface, so migrating changes only the import.
- **Login method from the salt, MD5 on request.** The router's salt length
  selects MD5 (16 bytes) or EC-SRP (49 bytes, a 33-byte server key and a
  16-byte salt). The client offers its EC-SRP public key up front, as RouterOS
  clients do, so one round trip serves both. Since the router chooses, a host
  posing as it could pick MD5 and take the proof away to guess the password
  offline, so MD5 is refused unless `Options.allowLegacyMd5` is set
  (`connectWith`); `connect` keeps its four parameters and EC-SRP only.
- **Reliable sends.** Each DATA packet is resent on a fixed schedule (150, 250,
  500, 900 and 1500 ms) until the router acknowledges it; packets that arrive
  meanwhile are acknowledged and kept. Each wait ends at a deadline taken when
  it starts, so datagrams from other hosts cannot extend it.
- **Counters in a `kv.Store`.** The send and receive counters and the
  unread output change on every call, and a struct passed into a module
  function is a copy, so they live in a store the `Session` holds.
- **Only the router's packets count.** A packet must carry the session key
  and come from the router's MAC; anything else, and any datagram shorter than
  a header, is dropped. Duplicates are dropped by the receive counter.
- **Best-effort interface bind.** The socket is bound to `iface` when the
  kernel allows it and left unbound otherwise, so an unprivileged run still
  works on a host with one link.

## Errors

The deck throws an `Error` of kind `"mactelnet"` for a failed login (with the
router's text), an MD5 login without `allowLegacyMd5`, an unknown local
interface, a malformed MAC address, a router that never sends a salt and a salt
of an unknown length. These come from the
caller's input or the router's refusal, not from a status or code the router
reports, so there is no error struct (as for `@jennifer/statsd`, M28.57).

A router that does not acknowledge the retransmit schedule is the generic
kind `"timeout"`, and console output over the buffer cap is `"limit"`. The receive loop catches only `net`'s `"timeout"`, which
means no packet yet; every other error, the generic kinds included, goes on
unchanged. Any failure in `connect` closes the socket and the session state.

## Security and limits

- **Cleartext.** The password is never sent (EC-SRP sends a proof, MD5 a
  digest that allows an offline guess, hence its opt-in), but the session
  itself is unencrypted. Anyone on the segment reads
  it, and can forge packets from the router's MAC with a guessed 16-bit
  session key. Use it on a trusted wire to set an address, then switch to
  api-ssl.
- **Datagrams** are read up to 1600 bytes; a control block's declared length
  is clipped to the packet.
- **Bounded waits.** A send gives up after about 3.3 seconds and `recv`
  returns by its `timeoutMs`, however many datagrams arrive meanwhile; the
  login waits at most 20 polls for the salt and for the end of authentication.
- **Console buffer.** Output not yet read with `recv` is held up to
  `MAX_CONSOLE_CHARS` (1 Mi characters). The packet that would pass it throws
  kind `"limit"` and is left unacknowledged and uncounted, so the router
  resends it and nothing is lost once `recv` drains the buffer. The cap also
  bounds the cost of appending to the buffer, which copies it.

## Testing and validation

`src/mactelnet_test.j` covers the header layouts (client and router), control
blocks, the byte helpers, the MD5 proof, the EC-SRP wiring and MAC parsing.
Sessions run against a fake MAC-Telnet peer on a loopback UDP port, reached
through the private `openSession` instead of the broadcast address: an MD5
login with the password checked, a command echoed with a spoofed packet from
another MAC dropped, an EC-SRP login (the peer checks only the proof's
length, since `crypto` has no router side of EC-SRP), a router ending the
session, a wrong password, an MD5 router refused before any proof reaches it,
and a silent peer that gives kind `"timeout"`. A flood of foreign datagrams
leaves the send schedule and `recv`'s deadline intact, and a full console
buffer refuses a packet without acknowledging it.
Runt datagrams are dropped, and a socket closed under a read is kind
`"closed"`.

The EC-SRP arithmetic itself is tested in `jennifer`'s `crypto` library,
where a client and a server half derive the same key. The tests never reach a router; the example needs
one, so CI parses it only.

## Known limitations and open questions

- No window-size changes and no keepalive; an idle session may be dropped by
  the router.
- A UDP read does not wake for `task.cancel`, so a cancelled task stops only
  when its read deadline passes.

## Dependencies on the interpreter

- The floor is `>=0.27.0`, for the UTF-8 codecs of `encoding.encode` /
  `decode` and `strings.replicate`; the bundled module is deprecated from
  0.26.0 (M30.1).
- `crypto.mtweiKeygen` / `mtweiId` / `mtweiClientKey` (EC-SRP) and
  `net.bindToDevice`, which stay in the interpreter after the bundled module is
  removed, plus `net`'s broadcast UDP and `kv`.
- The `net` capability and Linux, so the default `jennifer` binary only.
