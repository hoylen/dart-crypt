// Copyright (c) 2015, 2017, Hoylen Sue. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.
//
// Tests crypt using SHA-256.

library crypt.test;

import 'dart:async';

import 'package:test/test.dart';

import 'package:crypt/crypt.dart';

//----------------------------------------------------------------

Future main() async {
//----------------------------------------------------------------

  group("SHA256", () {
    //----------------
    // Examples from <http://www.akkadia.org/drepper/SHA-crypt.txt>

    test("examples from the specification", () {
      expect(new Crypt.sha256("Hello world!", salt: "saltstring").toString(),
          equals(r"$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5"));

      expect(
          new Crypt.sha256("Hello world!",
                  salt: "saltstringsaltstring", rounds: 10000)
              .toString(),
          equals(
              r"$5$rounds=10000$saltstringsaltst$3xv.VbSHBb41AL9AvLeujZkZRBAwqFMz2.opqey6IcA"));

      expect(
          new Crypt.sha256("This is just a test",
                  rounds: 5000, salt: "toolongsaltstring")
              .toString(),
          equals(
              r"$5$rounds=5000$toolongsaltstrin$Un/5jzAHMgOGZ5.mWJpuVolil07guHPvOW8mGRcvxa5"));

      expect(
          new Crypt.sha256(
                  r"a very much longer text to encrypt.  This one even stretches over morethan one line.",
                  rounds: 1400,
                  salt: "anotherlongsaltstring")
              .toString(),
          equals(
              r"$5$rounds=1400$anotherlongsalts$Rx.j8H.h8HjEDGomFU8bDkXm3XIUnzyxf12oP84Bnq1"));

      expect(
          new Crypt.sha256(
                  "we have a short salt string but not a short password",
                  rounds: 77777,
                  salt: "short")
              .toString(),
          equals(
              r"$5$rounds=77777$short$JiO1O3ZpDAxGJeaDIuqCoEFysAe1mZNJRs3pw0KQRd/"));

      expect(
          new Crypt.sha256("a short string",
                  rounds: 123456, salt: "asaltof16chars..")
              .toString(),
          equals(
              r"$5$rounds=123456$asaltof16chars..$gP3VQ/6X7UUEW3HkBn2w1/Ptq2jxPyzV/cZKmF/wJvD"));

      expect(
          new Crypt.sha256("the minimum number is still observed",
                  rounds: 10, salt: "roundstoolow")
              .toString(),
          equals(
              r"$5$rounds=1000$roundstoolow$yfvwcWrQ8l/K0DAWyuPMDNHpIVlTQebY9l/gL972bIC"));
    });

    //----------------
    // Examples from <http://php.net/manual/en/function.crypt.php>

    test("examples from PHP crypt documentation", () {
      expect(
          new Crypt.sha256("rasmuslerdorf",
                  rounds: 5000, salt: "usesomesillystringforsalt")
              .toString(),
          equals(
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
      expect(
          new Crypt.sha256("p@ssw0rd", salt: "abcdefghijklmnop").toString(),
          equals(
              r"$5$abcdefghijklmnop$gUWLu9sDI2Qvs112Xb8jmgD3ySIRE5ek63jk6ybSs7D"));

      expect(
          new Crypt.sha256("p@ssw0rd", salt: "").toString(),
          equals(
              r"$5$$f7mf/BhIj6wTH19qEbJEyGQ3m2RX7ktRmuNxiqvk./3")); // empty string salt

      expect(
          new Crypt.sha256("", salt: "abcdefghijklmnop").toString(),
          equals(
              r"$5$abcdefghijklmnop$p99E2fxZB/BTl9j.a2VRY5z71zEP761isnVBuiGlzV3")); // empty string key

      expect(
          new Crypt.sha256("", salt: "").toString(),
          equals(
              r"$5$$3c2QQ0KjIU1OLtB29cl8Fplc2WN7X89bnoEjaR7tWu.")); // empty string both

      expect(
          new Crypt.sha256("p@ssw0rd", rounds: 999, salt: "abcdefghijklmnop")
              .toString(),
          equals(
              r"$5$rounds=1000$abcdefghijklmnop$42HwcxWRyiYsdBB0xFqLRQ6qB8tD9/1n7XP4lIh73h5")); // minimum rounds

      expect(
          new Crypt.sha256("p@ssw0rd", rounds: 0, salt: "abcdefghijklmnop")
              .toString(),
          equals(
              r"$5$rounds=1000$abcdefghijklmnop$42HwcxWRyiYsdBB0xFqLRQ6qB8tD9/1n7XP4lIh73h5")); // minimum rounds
    });

    //----------------
    // Compare

    test("parsing crypt format strings", () {
      var a = new Crypt(
          r"$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5");

      expect(a.type, equals(Crypt.idSha256));
      expect(a.rounds, isNull);
      expect(a.salt, equals("saltstring"));
      expect(a.hash, equals("5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5"));

      a = new Crypt(
          r"$5$rounds=10000$saltstringsaltst$3xv.VbSHBb41AL9AvLeujZkZRBAwqFMz2.opqey6IcA");

      expect(a.type, equals(Crypt.idSha256));
      expect(a.rounds, equals(10000));
      expect(a.salt, equals("saltstringsaltst"));
      expect(a.hash, equals("3xv.VbSHBb41AL9AvLeujZkZRBAwqFMz2.opqey6IcA"));
    });

    //----------------
    // Compare

    test("compare", () {
      final secret = "p@ssw0rd";

      expect(new Crypt.sha256(secret).match(secret), isTrue);
      expect(new Crypt.sha256(secret, rounds: 1000).match(secret), isTrue);
      expect(new Crypt.sha256(secret, salt: "foobar").match(secret), isTrue);
      expect(new Crypt.sha256(secret, salt: "").match(secret), isTrue);

      final wrong = "!" + secret;

      expect(new Crypt.sha256(secret).match(wrong), isFalse);
      expect(new Crypt.sha256(secret, rounds: 1000).match(wrong), isFalse);
      expect(new Crypt.sha256(secret, salt: "foobar").match(wrong), isFalse);
      expect(new Crypt.sha256(secret, salt: "").match(wrong), isFalse);
    });

    /*
    //----------------
    // Warning: maximum rounds takes about 2 hours 48 minutes to run (on a 2 GHz Intel Core i7).
    // So it is normally not executed.

    test("maximum number of rounds", () {
      // Note: specifying a greater number of rounds results in the maximum of 999,999,999 being used
      expect(
          new Crypt.sha256("p@ssw0rd",
              rounds: 1000000000, salt: "abcdefghijklmnop").toString(),
          equals(
              r"$5$rounds=999999999$abcdefghijklmnop$/SLCBuVBB9IpRIt4hSBKg0PYJYP221Gb7rw34Jo48T/"));
    }, skip: "takes a long time to run (about 3 hours)");
    */

    //----------------

    test("timing", () async {
      final rounds = 50000;
      final start = new DateTime.now();
      final hash =
          new Crypt.sha256("p@ssw0rd", rounds: rounds, salt: "abcdefghijklmnop")
              .toString();
      final finish = new DateTime.now();

      final delay = finish.difference(start);
      // print("SHA-256: ${rounds} rounds: calculation time=${delay}");

      expect(delay, greaterThan(const Duration(milliseconds: 100)),
          reason: "Your computer is too fast!");
      expect(hash, startsWith(r"$5$"));
    });
  });
}
