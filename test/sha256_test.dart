// Copyright (c) 2015, Hoylen Sue. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.
//
// Tests crypt using SHA-256.

library crypt.test;

import 'dart:async';

import 'package:unittest/unittest.dart';
import 'package:unittest/vm_config.dart';

import 'package:crypt/crypt.dart';

//----------------------------------------------------------------

Future main() async {
  useVMConfiguration();

//----------------------------------------------------------------

  group("SHA256", () {

    //----------------
    // Examples from <http://www.akkadia.org/drepper/SHA-crypt.txt>

    test("examples from the specification", () {
      expect(Crypt.sha256("Hello world!", salt: "saltstring"),
          equals(r"$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5"));

      expect(Crypt.sha256("Hello world!",
          salt: "saltstringsaltstring", rounds: 10000), equals(
          r"$5$rounds=10000$saltstringsaltst$3xv.VbSHBb41AL9AvLeujZkZRBAwqFMz2.opqey6IcA"));

      expect(Crypt.sha256("This is just a test",
          rounds: 5000, salt: "toolongsaltstring"), equals(
          r"$5$rounds=5000$toolongsaltstrin$Un/5jzAHMgOGZ5.mWJpuVolil07guHPvOW8mGRcvxa5"));

      expect(Crypt.sha256(
          r"a very much longer text to encrypt.  This one even stretches over morethan one line.",
          rounds: 1400, salt: "anotherlongsaltstring"), equals(
          r"$5$rounds=1400$anotherlongsalts$Rx.j8H.h8HjEDGomFU8bDkXm3XIUnzyxf12oP84Bnq1"));

      expect(Crypt.sha256(
          "we have a short salt string but not a short password",
          rounds: 77777, salt: "short"), equals(
          r"$5$rounds=77777$short$JiO1O3ZpDAxGJeaDIuqCoEFysAe1mZNJRs3pw0KQRd/"));

      expect(Crypt.sha256("a short string",
          rounds: 123456, salt: "asaltof16chars.."), equals(
          r"$5$rounds=123456$asaltof16chars..$gP3VQ/6X7UUEW3HkBn2w1/Ptq2jxPyzV/cZKmF/wJvD"));

      expect(Crypt.sha256("the minimum number is still observed",
          rounds: 10, salt: "roundstoolow"), equals(
          r"$5$rounds=1000$roundstoolow$yfvwcWrQ8l/K0DAWyuPMDNHpIVlTQebY9l/gL972bIC"));
    });

    //----------------
    // Examples from <http://php.net/manual/en/function.crypt.php>

    test("examples from PHP crypt documentation", () {
      expect(Crypt.sha256("rasmuslerdorf",
          rounds: 5000, salt: "usesomesillystringforsalt"), equals(
          r"$5$rounds=5000$usesomesillystri$KqJWpanXZHKq2BOB43TSaYhEWsQ1Lr5QNyPCDH/Tp.6"));
    });

    //----------------
    // Examples generated using the PHP implementation of crypt.
    //
    // Run this command:
    //   php -f filename.php
    // On input files that contains:
    //   <?php echo crypt('p@ssw0rd','$5$rounds=999$abcdefghijklmnop$'), "\n"; ?>

    test("edge cases", () {
      expect(Crypt.sha256("p@ssw0rd", salt: "abcdefghijklmnop"), equals(
          r"$5$abcdefghijklmnop$gUWLu9sDI2Qvs112Xb8jmgD3ySIRE5ek63jk6ybSs7D"));

      expect(Crypt.sha256("p@ssw0rd", salt: ""), equals(
          r"$5$$f7mf/BhIj6wTH19qEbJEyGQ3m2RX7ktRmuNxiqvk./3")); // empty string salt

      expect(Crypt.sha256("", salt: "abcdefghijklmnop"), equals(
          r"$5$abcdefghijklmnop$p99E2fxZB/BTl9j.a2VRY5z71zEP761isnVBuiGlzV3")); // empty string key

      expect(Crypt.sha256("", salt: ""), equals(
          r"$5$$3c2QQ0KjIU1OLtB29cl8Fplc2WN7X89bnoEjaR7tWu.")); // empty string both

      expect(Crypt.sha256("p@ssw0rd",
          rounds: 999, salt: "abcdefghijklmnop"), equals(
          r"$5$rounds=1000$abcdefghijklmnop$42HwcxWRyiYsdBB0xFqLRQ6qB8tD9/1n7XP4lIh73h5")); // minimum rounds

      expect(Crypt.sha256("p@ssw0rd",
          rounds: 0, salt: "abcdefghijklmnop"), equals(
          r"$5$rounds=1000$abcdefghijklmnop$42HwcxWRyiYsdBB0xFqLRQ6qB8tD9/1n7XP4lIh73h5")); // minimum rounds
    });

    //----------------
    // Warning: maximum rounds takes about 2 hours 48 minutes to run (on a 2 GHz Intel Core i7).
    // So it is normally not executed.

    skip_test("maximum number of rounds", () {
      // Note: specifying a greater number of rounds results in the maximum of 999,999,999 being used
      expect(Crypt.sha256("p@ssw0rd",
          rounds: 1000000000, salt: "abcdefghijklmnop"), equals(
          r"$5$rounds=999999999$abcdefghijklmnop$/SLCBuVBB9IpRIt4hSBKg0PYJYP221Gb7rw34Jo48T/"));
    });

    //----------------

    skip_test("timing", () async {
      var rounds = 50000;
      var start = new DateTime.now();
      var hash = Crypt.sha256("p@ssw0rd",
          rounds: rounds, salt: "abcdefghijklmnop");
      var finish = new DateTime.now();

      var delay = finish.difference(start);
      print(
          "SHA-256: ${rounds} rounds: calculation time=${delay} hash=${hash}");

      expect(delay, greaterThan(new Duration(milliseconds: 100)),
          reason: "Your computer is too fast!");
      expect(hash, startsWith(r"$5$"));
    });
  });
}

//EOF
