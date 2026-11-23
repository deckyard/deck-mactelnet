# SPDX-License-Identifier: LGPL-3.0-only
# SPDX-FileCopyrightText: Copyright (C) 2026 mplx <mplx@jennifer-lang.dev>
# pragma-jennifer-version: >=0.27.0

/**
 * White-box tests for the entry module: jennifer test src/mactelnet_test.j
 *
 * The wire codec (headers, control blocks, byte helpers), the MD5 proof, the
 * EC-SRP wiring and MAC parsing are tested directly. Sessions run against
 * `fakeRouter`, a MAC-Telnet peer on a loopback UDP port that answers the way a
 * RouterOS device does; `openSession` sends to it instead of the broadcast
 * address, and "lo" stands in for the local interface.
 */
use testing;
use task;
use time;

func hex(b as bytes) {
    return encoding.toText("hex", $b);
}

func zeros(n as int) {
    return binary.make($n);
}

func testByteHelpers() {
    testing.assertEqual(hex(u16be(0xabcd)), "abcd");
    testing.assertEqual(hex(u16le(0xabcd)), "cdab");
    testing.assertEqual(hex(u32be(0x01020304)), "01020304");
    testing.assertEqual(readU16be(u16be(0x1234), 0), 0x1234);
    testing.assertEqual(readU32be(u32be(0x0a0b0c0d), 0), 0x0a0b0c0d);
}

func testParseMac() {
    testing.assertEqual(hex(parseMac("aa:bb:cc:dd:ee:ff")), "aabbccddeeff");
    testing.assertEqual(hex(parseMac("AA:BB:CC:DD:EE:FF")), "aabbccddeeff");
    testing.assertEqual(hex(parseMac("aabb-ccdd-eeff")), "aabbccddeeff");
    testing.assertEqual(hex(parseMac("aabbccddeeff")), "aabbccddeeff");
    testing.assertEqual(formatMac(parseMac("aa:bb:cc:dd:ee:ff")), "aa:bb:cc:dd:ee:ff");
}

func badMac() {
    parseMac("aa:bb:cc");
}

func testParseMacRejectsBadLength() {
    testing.assertThrows("badMac", "mactelnet");
}

func testBuildHeaderClientLayout() {
    def src as bytes init parseMac("01:02:03:04:05:06");
    def dst as bytes init parseMac("aa:bb:cc:dd:ee:ff");
    def h as bytes init buildHeader(PTYPE_DATA, $src, $dst, 0xabcd, 0x01020304);
    # ver=01 ptype=01 src dst seskey(BE)=abcd clienttype=0015 counter(BE)=01020304
    testing.assertEqual(len($h), 22);
    testing.assertEqual(hex($h), "0101010203040506aabbccddeeffabcd001501020304");
}

func testParseHeaderServerLayout() {
    # Server->client packets carry the session key at offset 16 (client type at
    # 14), the mirror of the client layout buildHeader emits.
    def sp as bytes;
    $sp[] = 1;
    $sp[] = PTYPE_ACK;
    $sp = binary.join([
        $sp,
        parseMac("010203040506"),
        parseMac("0a0b0c0d0e0f"),
        u16be(0x0015),
        u16be(0xbeef),
        u32be(0x00000064)
    ]);
    def hd as Header init parseHeader($sp);
    testing.assertEqual($hd.ptype, PTYPE_ACK);
    testing.assertEqual($hd.seskey, 0xbeef);
    testing.assertEqual($hd.counter, 0x64);
}

func testControlBlockFraming() {
    testing.assertEqual(hex(controlBlock(CPTYPE_BEGINAUTH, emptyBytes())), "563412ff0000000000");
    def two as bytes;
    $two[] = 0xaa;
    $two[] = 0xbb;
    testing.assertEqual(hex(controlBlock(CPTYPE_PASSWORD, $two)), "563412ff0200000002aabb");
}

func testMatchMagic() {
    def yes as bytes;
    $yes[] = 0x56;
    $yes[] = 0x34;
    $yes[] = 0x12;
    $yes[] = 0xff;
    $yes[] = 0x99;
    testing.assertEqual(matchMagic($yes, 0), true);
    def no as bytes;
    $no[] = 0x00;
    $no[] = 0x34;
    $no[] = 0x12;
    $no[] = 0xff;
    testing.assertEqual(matchMagic($no, 0), false);
}

func testMd5Password() {
    def salt as bytes init zeros(16);
    def pw as bytes init md5Password("test", $salt);
    # 0x00 followed by a 16-byte digest.
    testing.assertEqual(len($pw), 17);
    testing.assertEqual($pw[0], 0);
    # Cross-check the exact preimage: MD5(0x00 + password + salt).
    def zero as bytes;
    $zero[] = 0;
    def md as bytes init hash.compute("md5", binary.join([$zero, utf8("test"), $salt]));
    testing.assertEqual(hex($pw[1..17]), hex($md));
}

func testLoginKey() {
    def kp as crypto.Keypair init crypto.mtweiKeygen();
    def lk as bytes init loginKey("ab", $kp.public);
    # "ab" + 0x00 + 33-byte public key.
    testing.assertEqual(len($lk), 36);
    testing.assertEqual($lk[0], 0x61);
    testing.assertEqual($lk[1], 0x62);
    testing.assertEqual($lk[2], 0);
    testing.assertEqual(hex($lk[3..36]), hex($kp.public));
}

func testEcSrpWiring() {
    def kp as crypto.Keypair init crypto.mtweiKeygen();
    testing.assertEqual(len($kp.public), 33);
    testing.assertEqual(len($kp.private), 32);
    def salt16 as bytes init zeros(16);
    def val as bytes init crypto.mtweiId("admin", "pw", $salt16);
    testing.assertEqual(len($val), 32);
    # A second keypair's public key is a valid on-curve server key for wiring.
    def sk as crypto.Keypair init crypto.mtweiKeygen();
    def resp as bytes init crypto.mtweiClientKey($kp.private, $sk.public, $kp.public, $val);
    testing.assertEqual(len($resp), 32);
}

# SECURITY: a datagram shorter than a MACtelnet header from any LAN peer must be
# dropped inside recvPacket (not returned, not thrown), so a single runt cannot
# abort the session with an out-of-bounds error in parseHeader. The next
# full-length datagram is still delivered, and a runt with nothing behind it
# times out to empty rather than throwing.
func testRecvPacketDropsRunt() {
    def recvSock as net.UDPSocket init net.listenUDP("127.0.0.1:0");
    def addr as string init net.address($recvSock);
    def sender as net.UDPSocket init net.listenUDP("127.0.0.1:0");
    def sess as Session init Session{
        sock: $recvSock,
        state: kv.open(),
        srcmac: emptyBytes(),
        dstmac: emptyBytes(),
        seskey: 0
    };
    def runt as bytes init encoding.encode("utf-8", "hello");
    def full as bytes init binary.make(HEADER_LEN);
    net.sendTo($sender, $addr, $runt);
    net.sendTo($sender, $addr, $full);
    testing.assertEqual(len(recvPacket($sess, 2000)), HEADER_LEN); # runt skipped, full returned
    net.sendTo($sender, $addr, $runt);
    testing.assertEqual(len(recvPacket($sess, 300)), 0); # lone runt -> timeout, no throw
    net.close($recvSock);
    net.close($sender);
}

# --- a fake MAC-Telnet peer ----------------------------------------------------

def const ROUTER_MAC as string init "aa:bb:cc:dd:ee:ff";

# srvHeader builds a router's 22-byte header: the router MAC as the source,
# client type at 14, the session key at 16 (the mirror of the client layout).
func srvHeader(ptype as int, seskey as int, counter as int) {
    def lead as bytes;
    $lead[] = 1;
    $lead[] = $ptype;
    return binary.join([
        $lead,
        parseMac(ROUTER_MAC),
        binary.make(6),
        u16be(0x0015),
        u16be($seskey),
        u32be($counter)
    ]);
}

# Login is what the peer read from a client's DATA payload.
def struct Login {
    beginAuth as bool,
    hasPassword as bool,
    password as bytes,
    plain as string
};

func readLogin(payload as bytes) {
    def l as Login init Login{
        beginAuth: false,
        hasPassword: false,
        password: emptyBytes(),
        plain: ""
    };
    def off as int init 0;
    while ($off + 9 <= len($payload) and matchMagic($payload, $off)) {
        def clen as int init readU32be($payload, $off + 5);
        def data as bytes init $payload[$off + 9..$off + 9 + $clen];
        if ($payload[$off + 4] == CPTYPE_BEGINAUTH) {
            $l.beginAuth = true;
        } elseif ($payload[$off + 4] == CPTYPE_PASSWORD) {
            $l.hasPassword = true;
            $l.password = $data;
        }
        $off = $off + 9 + $clen;
    }
    $l.plain = encoding.decode("utf-8", $payload[$off..]);
    return $l;
}

# proofOk checks a login's password proof the way the router would: the MD5
# digest for a 16-byte salt, only the length for EC-SRP.
func proofOk(proof as bytes, password as string, salt as bytes) {
    if (len($salt) != 16) {
        return len($proof) == 32;
    }
    def zero as bytes init binary.make(1);
    def digest as bytes init hash.compute("md5", binary.join([$zero, utf8($password), $salt]));
    return $proof == binary.concat($zero, $digest);
}

# fakeRouter answers MAC-Telnet sessions on `sock` until a client ends one or
# nothing arrives for `idleMs`, and returns the console lines it was sent,
# with "<proof>" where a password proof arrived.
# A `salt` of 16 bytes selects MD5 and the password is checked; one of 49 bytes
# selects EC-SRP, where only the proof's length is checked (the router side of
# EC-SRP is not in `crypto`). "/quit" makes the router end the session.
func fakeRouter(sock as net.UDPSocket, password as string, salt as bytes, idleMs as int) {
    def lines as list of string init [];
    def out as int init 0;
    while (true) {
        net.setReadDeadline($sock, $idleMs);
        def dg as net.Datagram;
        try {
            $dg = net.recvFrom($sock, MAX_DATAGRAM);
        } catch (e) {
            if ($e.kind == "timeout") {
                return $lines;
            }
            throw $e;
        }
        def pkt as bytes init $dg.data;
        def seskey as int init readU16be($pkt, 14);
        def ptype as int init $pkt[1];
        if ($ptype == PTYPE_SESSIONSTART) {
            net.sendTo($sock, $dg.peer, srvHeader(PTYPE_ACK, $seskey, 0));
        } elseif ($ptype == PTYPE_END) {
            return $lines;
        } elseif ($ptype == PTYPE_DATA) {
            def payload as bytes init $pkt[HEADER_LEN..];
            net.sendTo(
                $sock,
                $dg.peer,
                srvHeader(PTYPE_ACK, $seskey, readU32be($pkt, 18) + len($payload)));
            def l as Login init readLogin($payload);
            if ($l.hasPassword) {
                $lines[] = "<proof>";
            }
            if ($l.hasPassword and not proofOk($l.password, $password, $salt)) {
                # a refused login: the router's text, then the end of the session
                def refusal as bytes init utf8("Login failed\r\n");
                net.sendTo(
                    $sock,
                    $dg.peer,
                    binary.concat(srvHeader(PTYPE_DATA, $seskey, $out), $refusal));
                net.sendTo($sock, $dg.peer, srvHeader(PTYPE_END, $seskey, 0));
                return $lines;
            }
            def body as bytes;
            if ($l.beginAuth) {
                $body = controlBlock(CPTYPE_PASSSALT, $salt);
            } elseif ($l.hasPassword) {
                $body = binary.concat(
                    controlBlock(CPTYPE_END_AUTH, emptyBytes()),
                    utf8("logged in\r\n"));
            } elseif (strings.startsWith($l.plain, "/quit")) {
                $lines[] = $l.plain;
                net.sendTo($sock, $dg.peer, srvHeader(PTYPE_END, $seskey, 0));
                return $lines;
            } else {
                $lines[] = $l.plain;
                # another host's MAC with the right session key and a later
                # counter: the client must drop it
                def spoof as bytes init binary.concat(
                    srvHeader(PTYPE_DATA, $seskey, $out + 1000),
                    utf8("SPOOFED\r\n"));
                $spoof[2] = 0x02;
                net.sendTo($sock, $dg.peer, $spoof);
                $body = utf8("OK\r\n");
            }
            net.sendTo($sock, $dg.peer, binary.concat(srvHeader(PTYPE_DATA, $seskey, $out), $body));
            $out = $out + len($body);
        }
    }
}

# legacy opts in to the MD5 login of an old router.
func legacy(o as Options) {
    def out as Options init $o;
    $out.allowLegacyMd5 = true;
    return $out;
}

func md5Salt() {
    return utf8("mactelnet16bsalt");
}

func ecSrpSalt() {
    def server as crypto.Keypair init crypto.mtweiKeygen();
    return binary.concat($server.public, binary.make(16));
}

func testMd5Session() {
    def sock as net.UDPSocket init net.listenUDP("127.0.0.1:0");
    defer net.close($sock);
    def peer as task of list of string init spawn {
        return fakeRouter($sock, "test", md5Salt(), 2000);
    };
    def s as Session init openSession(
        legacy(options("lo", ROUTER_MAC, "admin", "test")),
        net.address($sock));
    testing.assertContains(recv($s, 800), "logged in");
    send($s, "/ip address print\r\n");
    def out as string init recv($s, 800);
    testing.assertContains($out, "OK");
    testing.assertFalse(strings.contains($out, "SPOOFED"));
    testing.assertFalse(closed($s));
    close($s);
    testing.assertEqual(task.wait($peer), ["<proof>", "/ip address print\r\n"]);
}

func testEcSrpSession() {
    def sock as net.UDPSocket init net.listenUDP("127.0.0.1:0");
    defer net.close($sock);
    def peer as task of list of string init spawn {
        return fakeRouter($sock, "", ecSrpSalt(), 2000);
    };
    def s as Session init openSession(options("lo", ROUTER_MAC, "admin", ""), net.address($sock));
    send($s, "/quit\r\n");
    recv($s, 500);
    testing.assertTrue(closed($s));
    close($s);
    testing.assertEqual(task.wait($peer), ["<proof>", "/quit\r\n"]);
}

func testAWrongPasswordIsAMactelnetError() {
    def sock as net.UDPSocket init net.listenUDP("127.0.0.1:0");
    defer net.close($sock);
    def peer as task of list of string init spawn {
        return fakeRouter($sock, "correct-horse", md5Salt(), 2000);
    };
    try {
        openSession(legacy(options("lo", ROUTER_MAC, "admin", "wrong")), net.address($sock));
        throw Error{kind: "missed", message: "a refused login"};
    } catch (e) {
        testing.assertEqual($e.kind, "mactelnet");
        testing.assertEqual($e.message, "mactelnet: login failed: Login failed");
    }
    task.wait($peer);
}

# A router that never answers (a wrong MAC, mac-server off) is kind "timeout"
# once the retransmit schedule runs out.
func testASilentRouterIsATimeout() {
    def sock as net.UDPSocket init net.listenUDP("127.0.0.1:0");
    defer net.close($sock);
    try {
        openSession(options("lo", ROUTER_MAC, "admin", ""), net.address($sock));
        throw Error{kind: "missed", message: "a timeout"};
    } catch (e) {
        testing.assertEqual($e.kind, "timeout");
    }
}

func testAnUnknownInterfaceIsAMactelnetError() {
    try {
        connect("no-such-if0", ROUTER_MAC, "admin", "");
        throw Error{kind: "missed", message: "a missing interface"};
    } catch (e) {
        testing.assertEqual($e.kind, "mactelnet");
        testing.assertContains($e.message, "no such network interface");
    }
    try {
        connectWith(legacy(options("no-such-if0", ROUTER_MAC, "admin", "")));
        throw Error{kind: "missed", message: "a missing interface"};
    } catch (e) {
        testing.assertEqual($e.kind, "mactelnet");
    }
}

# Only a timeout reads as "nothing arrived": a socket closed under the blocked
# read goes on as kind "closed".
func testRecvPacketPassesOnAClosedSocket() {
    def sock as net.UDPSocket init net.listenUDP("127.0.0.1:0");
    def sess as Session init Session{
        sock: $sock,
        state: kv.open(),
        srcmac: emptyBytes(),
        dstmac: emptyBytes(),
        seskey: 0
    };
    def closer as task of null init spawn {
        time.sleep(time.fromMilliseconds(200));
        net.close($sock);
        return null;
    };
    try {
        recvPacket($sess, 5000);
        throw Error{kind: "missed", message: "a closed socket"};
    } catch (e) {
        testing.assertEqual($e.kind, "closed");
    }
    task.wait($closer);
}

# A router that offers only the MD5 login is refused before any password proof
# is sent: the proof would let it, or anyone watching, guess the password
# offline. The opt-in is shown by testMd5Session.
func testAnMd5OnlyRouterIsRefusedByDefault() {
    def sock as net.UDPSocket init net.listenUDP("127.0.0.1:0");
    defer net.close($sock);
    def peer as task of list of string init spawn {
        # the refused client goes quiet: the router stops 500 ms later
        return fakeRouter($sock, "test", md5Salt(), 500);
    };
    testing.assertFalse(options("lo", ROUTER_MAC, "admin", "test").allowLegacyMd5);
    try {
        openSession(options("lo", ROUTER_MAC, "admin", "test"), net.address($sock));
        throw Error{kind: "missed", message: "a refused MD5 login"};
    } catch (e) {
        testing.assertEqual($e.kind, "mactelnet");
        testing.assertContains($e.message, "allowLegacyMd5");
    }
    testing.assertEqual(task.wait($peer), []);
}

# --- deadlines and the console buffer -----------------------------------------

# looseSession is a session on a loopback socket that sends to `target`, with
# the counters of a fresh login.
func looseSession(target as string) {
    def store as kv.Store init kv.open();
    kv.set($store, "out", "0", 0);
    kv.set($store, "in", "-1", 0);
    kv.set($store, "buf", "", 0);
    kv.set($store, "open", "1", 0);
    kv.set($store, "target", $target, 0);
    return Session{
        sock: net.listenUDP("127.0.0.1:0"),
        state: $store,
        srcmac: binary.make(6),
        dstmac: parseMac(ROUTER_MAC),
        seskey: 1234
    };
}

# flood sends a header-sized datagram that belongs to no session to `addr`
# every 20 ms, until `stop` holds "1" or eight seconds have passed.
func flood(addr as string, stop as kv.Store) {
    def sender as net.UDPSocket init net.listenUDP("127.0.0.1:0");
    defer net.close($sender);
    def junk as bytes init binary.make(32);
    $junk[0] = 1;
    for (def i in 0..400) {
        if (kv.get($stop, "stop") == "1") {
            return null;
        }
        net.sendTo($sender, $addr, $junk);
        time.sleep(time.fromMilliseconds(20));
    }
    return null;
}

func clockMs() {
    return time.unixMillis(time.now());
}

func msSince(start as int) {
    return clockMs() - $start;
}

# Datagrams for no session restart no wait: a send under a flood still times
# out on its schedule (about 3.3 seconds), and recv returns at its deadline.
func testAFloodCannotStretchTheWaits() {
    def sink as net.UDPSocket init net.listenUDP("127.0.0.1:0");
    defer net.close($sink);
    def s as Session init looseSession(net.address($sink));
    defer net.close($s.sock);
    def stop as kv.Store init kv.open();
    kv.set($stop, "stop", "0", 0);
    def flooder as task of null init spawn {
        return flood(net.address($s.sock), $stop);
    };
    def t0 as int init clockMs();
    try {
        sendReliable($s, buildHeader(PTYPE_SESSIONSTART, $s.srcmac, $s.dstmac, $s.seskey, 0));
        throw Error{kind: "missed", message: "a timeout"};
    } catch (e) {
        testing.assertEqual($e.kind, "timeout");
    }
    def sendMs as int init msSince($t0);
    $t0 = clockMs();
    testing.assertEqual(recv($s, 300), "");
    def recvMs as int init msSince($t0);
    kv.set($stop, "stop", "1", 0);
    task.wait($flooder);
    testing.assertTrue($sendMs < 5000);
    testing.assertTrue($recvMs < 1000);
}

# Console output nobody reads stops at 1 Mi characters (MAX_CONSOLE_CHARS): the
# packet that would pass it is kind "limit", neither acknowledged nor counted,
# so the router resends it, and it is taken once recv has drained the buffer.
func testUnreadConsoleOutputIsCapped() {
    def sink as net.UDPSocket init net.listenUDP("127.0.0.1:0");
    defer net.close($sink);
    def s as Session init looseSession(net.address($sink));
    defer net.close($s.sock);
    kv.set($s.state, "buf", strings.replicate("x", 1048574), 0);
    def pkt as bytes init binary.concat(srvHeader(PTYPE_DATA, 1234, 0), utf8("hello"));
    try {
        processData($s, $pkt);
        throw Error{kind: "missed", message: "a full buffer"};
    } catch (e) {
        testing.assertEqual($e.kind, "limit");
    }
    testing.assertEqual(getInt($s.state, "in"), -1);
    net.setReadDeadline($sink, 200);
    try {
        net.recvFrom($sink, MAX_DATAGRAM);
        throw Error{kind: "missed", message: "no ACK"};
    } catch (e) {
        testing.assertEqual($e.kind, "timeout");
    }
    testing.assertEqual(len(recv($s, 0)), 1048574);
    processData($s, $pkt);
    testing.assertEqual(recv($s, 0), "hello");
    testing.assertEqual(getInt($s.state, "in"), 0);
    testing.assertEqual(MAX_CONSOLE_CHARS, 1048576);
}
