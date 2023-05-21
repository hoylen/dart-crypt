// Copyright (c) 2015, 2017, Hoylen Sue. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.
//
// Tests crypt using SHA-256.

library crypt.test;

import 'dart:async';

import 'package:crypt/crypt.dart';
import 'package:test/test.dart';

//################################################################

class SpecTestVector {
  const SpecTestVector(this._params, this.input, this.expected);

  final String _params;
  final String input;
  final String expected;

  int? get rounds {
    final p = _params.split(r'$');
    expect(p.length == 3 || p.length == 4, isTrue);
    expect(p[0] == '' && p[1] == '5', isTrue);

    return (3 < p.length) ? int.parse(p[2].substring('rounds='.length)) : null;
  }

  String get salt {
    final p = _params.split(r'$');
    expect(p.length == 3 || p.length == 4, isTrue);
    expect(p[0] == '' && p[1] == '5', isTrue);

    return (3 < p.length) ? p[3] : p[2];
  }
}

//----------------------------------------------------------------
// Examples from line 990 of <http://www.akkadia.org/drepper/SHA-crypt.txt>

const specTestVectors = [
  SpecTestVector(r'$5$saltstring', 'Hello world!',
      r'$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5'),
  SpecTestVector(
      r'$5$rounds=10000$saltstringsaltstring',
      'Hello world!',
      r'$5$rounds=10000$saltstringsaltst$3xv.VbSHBb41AL9AvLeujZkZRBAwqFMz2.'
          'opqey6IcA'),
  SpecTestVector(
      r'$5$rounds=5000$toolongsaltstring',
      'This is just a test',
      r'$5$rounds=5000$toolongsaltstrin$Un/5jzAHMgOGZ5.mWJpuVolil07guHPvOW8'
          'mGRcvxa5'),
  SpecTestVector(
      r'$5$rounds=1400$anotherlongsaltstring',
      'a very much longer text to encrypt.  This one even stretches over more'
          'than one line.',
      r'$5$rounds=1400$anotherlongsalts$Rx.j8H.h8HjEDGomFU8bDkXm3XIUnzyxf12'
          'oP84Bnq1'),
  SpecTestVector(
      r'$5$rounds=77777$short',
      'we have a short salt string but not a short password',
      r'$5$rounds=77777$short$JiO1O3ZpDAxGJeaDIuqCoEFysAe1mZNJRs3pw0KQRd/'),
  SpecTestVector(
      r'$5$rounds=123456$asaltof16chars..',
      'a short string',
      r'$5$rounds=123456$asaltof16chars..$gP3VQ/6X7UUEW3HkBn2w1/Ptq2jxPyzV/'
          'cZKmF/wJvD'),
  SpecTestVector(
      r'$5$rounds=10$roundstoolow',
      'the minimum number is still observed',
      r'$5$rounds=1000$roundstoolow$yfvwcWrQ8l/K0DAWyuPMDNHpIVlTQebY9l/gL97'
          '2bIC'),
];

//################################################################

Future main() async {
  group('SHA256', () {
    //----------------
    // Examples from <http://www.akkadia.org/drepper/SHA-crypt.txt>

    test('examples from the specification', () {
      for (final v in specTestVectors) {
        final s =
            Crypt.sha256(v.input, salt: v.salt, rounds: v.rounds).toString();
        expect(s, equals(v.expected));
      }
    });

    //----------------
    // Examples from <http://php.net/manual/en/function.crypt.php>

    test('example from PHP crypt documentation', () {
      expect(
          Crypt.sha256('rasmuslerdorf',
                  rounds: 5000, salt: 'usesomesillystringforsalt')
              .toString(),
          equals(
              r'$5$rounds=5000$usesomesillystri$KqJWpanXZHKq2BOB43TSaYhEWsQ1Lr5QNyPCDH/Tp.6'));
    });

    //----------------
    // Examples generated using the PHP implementation of crypt.
    //
    // Run this command:
    //   php -f filename.php
    // On input files that contains:
    //   <?php echo crypt('p@ssw0rd','$5$rounds=999$abcdefghijklmnop$'), '\n'; ?>

    test('edge cases', () {
      expect(
          Crypt.sha256('p@ssw0rd', salt: 'abcdefghijklmnop').toString(),
          equals(
              r'$5$abcdefghijklmnop$gUWLu9sDI2Qvs112Xb8jmgD3ySIRE5ek63jk6ybSs7D'));

      expect(
          Crypt.sha256('p@ssw0rd', salt: '').toString(),
          equals(
              r'$5$$f7mf/BhIj6wTH19qEbJEyGQ3m2RX7ktRmuNxiqvk./3')); // empty string salt

      expect(
          Crypt.sha256('', salt: 'abcdefghijklmnop').toString(),
          equals(
              r'$5$abcdefghijklmnop$p99E2fxZB/BTl9j.a2VRY5z71zEP761isnVBuiGlzV3')); // empty string key

      expect(
          Crypt.sha256('', salt: '').toString(),
          equals(
              r'$5$$3c2QQ0KjIU1OLtB29cl8Fplc2WN7X89bnoEjaR7tWu.')); // empty string both

      expect(
          Crypt.sha256('p@ssw0rd', rounds: 999, salt: 'abcdefghijklmnop')
              .toString(),
          equals(
              r'$5$rounds=1000$abcdefghijklmnop$42HwcxWRyiYsdBB0xFqLRQ6qB8tD9/1n7XP4lIh73h5')); // minimum rounds

      expect(
          Crypt.sha256('p@ssw0rd', rounds: 0, salt: 'abcdefghijklmnop')
              .toString(),
          equals(
              r'$5$rounds=1000$abcdefghijklmnop$42HwcxWRyiYsdBB0xFqLRQ6qB8tD9/1n7XP4lIh73h5')); // minimum rounds
    });

    //----------------
    // Parsing components from the string

    test('parsing crypt format strings', () {
      var a =
          Crypt(r'$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5');

      expect(a.type, equals(Crypt.idSha256));
      expect(a.rounds, isNull);
      expect(a.salt, equals('saltstring'));
      expect(a.hash, equals('5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5'));

      a = Crypt(
          r'$5$rounds=10000$saltstringsaltst$3xv.VbSHBb41AL9AvLeujZkZRBAwqFMz2.opqey6IcA');

      expect(a.type, equals(Crypt.idSha256));
      expect(a.rounds, equals(10000));
      expect(a.salt, equals('saltstringsaltst'));
      expect(a.hash, equals('3xv.VbSHBb41AL9AvLeujZkZRBAwqFMz2.opqey6IcA'));
    });

    //----------------
    // Comparing hash to secret

    test('compare', () {
      const secret = 'p@ssw0rd';

      expect(Crypt.sha256(secret).match(secret), isTrue);
      expect(Crypt.sha256(secret, rounds: 1000).match(secret), isTrue);
      expect(Crypt.sha256(secret, salt: 'foobar').match(secret), isTrue);
      expect(Crypt.sha256(secret, salt: '').match(secret), isTrue);

      const wrong = '!$secret';

      expect(Crypt.sha256(secret).match(wrong), isFalse);
      expect(Crypt.sha256(secret, rounds: 1000).match(wrong), isFalse);
      expect(Crypt.sha256(secret, salt: 'foobar').match(wrong), isFalse);
      expect(Crypt.sha256(secret, salt: '').match(wrong), isFalse);
    });

    /*
    //----------------
    // Warning: maximum rounds takes about 2 hours 48 minutes to run (on a 2 GHz Intel Core i7).
    // So it is normally not executed.

    test('maximum number of rounds', () {
      // Note: specifying a greater number of rounds results in the maximum of 999,999,999 being used
      expect(
          Crypt.sha256('p@ssw0rd',
              rounds: 1000000000, salt: 'abcdefghijklmnop').toString(),
          equals(
              r'$5$rounds=999999999$abcdefghijklmnop$/SLCBuVBB9IpRIt4hSBKg0PYJYP221Gb7rw34Jo48T/'));
    }, skip: 'takes a long time to run (about 3 hours)');
    */

    //----------------

    test('timing', () async {
      const rounds = 200000;
      final start = DateTime.now();
      final hash =
          Crypt.sha256('p@ssw0rd', rounds: rounds, salt: 'abcdefghijklmnop')
              .toString();
      final finish = DateTime.now();

      final delay = finish.difference(start);
      // print('SHA-256: ${rounds} rounds: calculation time=${delay}');

      expect(delay, greaterThan(const Duration(milliseconds: 100)),
          reason: 'Your computer is too fast! Increase the number of rounds.');
      expect(hash, startsWith(r'$5$'));
    });

    //----------------
    /// Tests if the implementation rejects "$" in the caller provided salt.
    ///
    /// A dollar sign in the salt would cause problems for validators that
    /// simply split the crypt string on the dollar sign, to obtain all
    /// the parts.

    test('salt containing dollar sign rejected', () {
      const badSalt = r'dollar sign $ in salt';

      try {
        Crypt.sha256('p@ssw0rd', salt: badSalt);
        fail('dollar sign accepted in salt'); // may cause parsing problems
      } on ArgumentError catch (ex) {
        expect(ex.name, equals('salt'));
        expect(ex.invalidValue, equals(badSalt));
      }
    });
  });
}
