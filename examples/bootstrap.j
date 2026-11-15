#!/usr/bin/env -S jennifer run
# SPDX-License-Identifier: LGPL-3.0-only
# SPDX-FileCopyrightText: Copyright (C) 2026 mplx <mplx@jennifer-lang.dev>
# pragma-jennifer-version: >=0.26.0

/**
 * Give a fresh router its first address:
 * jennifer run examples/bootstrap.j iface router-mac user password address
 *
 * Opens a MAC-Telnet console on the local interface `iface` (for example
 * eth0), logs in, adds `address` (for example 192.168.88.10/24) to ether1 and
 * prints what the router answers. Pass "" for a blank password. Needs a
 * router on the same segment, so CI only parses it.
 */

use io;
use os;

import "../src/mactelnet.j" as mactelnet;

if (len(os.ARGS) < 6) {
    io.printf("usage: bootstrap.j iface router-mac user password address\n");
    exit 2;
}

def s as mactelnet.Session init mactelnet.connect(os.ARGS[1], os.ARGS[2], os.ARGS[3], os.ARGS[4]);
defer mactelnet.close($s);
io.printf("%s", mactelnet.recv($s, 1000));

mactelnet.send($s, "/ip address add address=" + os.ARGS[5] + " interface=ether1\r\n");
io.printf("%s", mactelnet.recv($s, 1500));
mactelnet.send($s, "/ip address print\r\n");
io.printf("%s\n", mactelnet.recv($s, 1500));
