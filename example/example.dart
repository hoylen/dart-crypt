// Copyright (c) 2015, 2016, 2017, 2020, Hoylen Sue. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

import 'package:crypt/crypt.dart';

void main() {
  // Creating crypt strings
  //
  // For example, when someone updates their password, generate a crypt hash
  // string from it and save the crypt hash string in a database. Never store
  // the plaintext password.

  // Default rounds and random salt generated
  final c1 = Crypt.sha256('p@ssw0rd');

  // Random salt generated
  final c2 = Crypt.sha256('p@ssw0rd', rounds: 10000);

  // Default rounds
  final c3 = Crypt.sha256('p@ssw0rd', salt: 'abcdefghijklmnop');

  // No defaults used
  final c4 = Crypt.sha256('p@ssw0rd', rounds: 10000, salt: 'abcdefghijklmnop');

  // SHA-512
  final d1 = Crypt.sha512('p@ssw0rd');

  print(c1);
  print(c2);
  print(c3);
  print(c4);
  print(d1);

  // Note: the crypt strings that have randomly generated salts will produce
  // different values every time the program runs. The crypt strings that uses
  // fixed salts, will always produce the same values.

  // Comparing a value to a crypt hash
  //
  // For example, the crypt hash string is stored in a database. When someone
  // tries to sign in, it is retrieved from the database and compared to the
  // password they have entered. If match returns true, they have provided the
  // original value that was used to create the crypt hash string.

  for (final hashString in [
    r'$5$zQUCjEzs9jnrRdCK$dbo1i9WjQjbUwOC4JCRAZHpfd31Dh676vI0L6w0dZw1',
    c1.toString(),
    c2.toString(),
    c3.toString(),
    c4.toString(),
    d1.toString(),
  ]) {
    // Parse the crypt string: this extracts the type, rounds and salt
    final h = Crypt(hashString);

    const correctValue = 'p@ssw0rd';
    const wrongValue = '123456';

    if (!h.match(correctValue)) {
      print('Error: unexpected non-match: $correctValue');
    }

    if (h.match(wrongValue)) {
      print('Error: unexpected match: $wrongValue');
    }
  }
}
