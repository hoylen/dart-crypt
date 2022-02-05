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
    expect(p[0] == '' && p[1] == '6', isTrue);

    return (3 < p.length) ? int.parse(p[2].substring('rounds='.length)) : null;
  }

  String get salt {
    final p = _params.split(r'$');
    expect(p.length == 3 || p.length == 4, isTrue);
    expect(p[0] == '' && p[1] == '6', isTrue);

    return (3 < p.length) ? p[3] : p[2];
  }
}

//----------------------------------------------------------------
// Examples from line 1776 of <http://www.akkadia.org/drepper/SHA-crypt.txt>

const specTestVectors = [
  SpecTestVector(
      r'$6$saltstring',
      'Hello world!',
      r'$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJu'
          'esI68u4OTLiBFdcbYEdFCoEOfaS35inz1'),
  SpecTestVector(
      r'$6$rounds=10000$saltstringsaltstring',
      'Hello world!',
      r'$6$rounds=10000$saltstringsaltst$OW1/O6BYHV6BcXZu8QVeXbDWra3Oeqh0sb'
          'HbbMCVNSnCM/UrjmM0Dp8vOuZeHBy/YTBmSK6H9qs/y3RnOaw5v.'),
  SpecTestVector(
      r'$6$rounds=5000$toolongsaltstring',
      'This is just a test',
      r'$6$rounds=5000$toolongsaltstrin$lQ8jolhgVRVhY4b5pZKaysCLi0QBxGoNeKQ'
          'zQ3glMhwllF7oGDZxUhx1yxdYcz/e1JSbq3y6JMxxl8audkUEm0'),
  SpecTestVector(
      r'$6$rounds=1400$anotherlongsaltstring',
      'a very much longer text to encrypt.  This one even stretches over more'
          'than one line.',
      r'$6$rounds=1400$anotherlongsalts$POfYwTEok97VWcjxIiSOjiykti.o/pQs.wP'
          'vMxQ6Fm7I6IoYN3CmLs66x9t0oSwbtEW7o7UmJEiDwGqd8p4ur1'),
  SpecTestVector(
      r'$6$rounds=77777$short',
      'we have a short salt string but not a short password',
      r'$6$rounds=77777$short$WuQyW2YR.hBNpjjRhpYD/ifIw05xdfeEyQoMxIXbkvr0g'
          'ge1a1x3yRULJ5CCaUeOxFmtlcGZelFl5CxtgfiAc0'),
  SpecTestVector(
      r'$6$rounds=123456$asaltof16chars..',
      'a short string',
      r'$6$rounds=123456$asaltof16chars..$BtCwjqMJGx5hrJhZywWvt0RLE8uZ4oPwc'
          'elCjmw2kSYu.Ec6ycULevoBK25fs2xXgMNrCzIMVcgEJAstJeonj1'),
  SpecTestVector(
      r'$6$rounds=10$roundstoolow',
      'the minimum number is still observed',
      r'$6$rounds=1000$roundstoolow$kUMsbe306n21p9R.FRkW3IGn.S9NPN0x50YhH1x'
          'hLsPuWGsUSklZt58jaTfF4ZEQpyUNGc0dqbpBYYBaHHrsX.'),
];
//################################################################

Future main() async {
  group('SHA512', () {
    //----------------
    // Examples from <http://www.akkadia.org/drepper/SHA-crypt.txt>

    test('examples from the specification', () {
      for (final v in specTestVectors) {
        final s =
            Crypt.sha512(v.input, salt: v.salt, rounds: v.rounds).toString();
        expect(s, equals(v.expected));
      }
    });

    //----------------
    // Examples from <http://php.net/manual/en/function.crypt.php>

    test('example from PHP crypt documentation', () {
      expect(
          Crypt.sha512('rasmuslerdorf',
                  rounds: 5000, salt: 'usesomesillystringforsalt')
              .toString(),
          equals(
              r'$6$rounds=5000$usesomesillystri$D4IrlXatmP7rx3P3InaxBeoomnAihCKRVQP22JZ6EY47Wc6BkroIuUUBOov1i.S5KPgErtP/EN5mcO.ChWQW21'));
    });

    //----------------
    // Parsing components from the string

    test('parsing crypt format strings', () {
      var a = Crypt(
          r'$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJu'
          'esI68u4OTLiBFdcbYEdFCoEOfaS35inz1');

      expect(a.type, equals(Crypt.idSha512));
      expect(a.rounds, isNull);
      expect(a.salt, equals('saltstring'));
      expect(
          a.hash,
          equals('svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3u'
              'BnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1'));

      a = Crypt(
          r'$6$rounds=10000$saltstringsaltst$OW1/O6BYHV6BcXZu8QVeXbDWra3Oeqh0sb'
          'HbbMCVNSnCM/UrjmM0Dp8vOuZeHBy/YTBmSK6H9qs/y3RnOaw5v.');

      expect(a.type, equals(Crypt.idSha512));
      expect(a.rounds, equals(10000));
      expect(a.salt, equals('saltstringsaltst'));
      expect(
          a.hash,
          equals('OW1/O6BYHV6BcXZu8QVeXbDWra3Oeqh0sb'
              'HbbMCVNSnCM/UrjmM0Dp8vOuZeHBy/YTBmSK6H9qs/y3RnOaw5v.'));
    });

    //----------------
    // Comparing hash to secret

    test('compare', () {
      const secret = 'p@ssw0rd';

      expect(Crypt.sha512(secret).match(secret), isTrue);
      expect(Crypt.sha512(secret, rounds: 1000).match(secret), isTrue);
      expect(Crypt.sha512(secret, salt: 'foobar').match(secret), isTrue);
      expect(Crypt.sha512(secret, salt: '').match(secret), isTrue);

      const wrong = '!$secret';

      expect(Crypt.sha512(secret).match(wrong), isFalse);
      expect(Crypt.sha512(secret, rounds: 1000).match(wrong), isFalse);
      expect(Crypt.sha512(secret, salt: 'foobar').match(wrong), isFalse);
      expect(Crypt.sha512(secret, salt: '').match(wrong), isFalse);
    });
  });
}
