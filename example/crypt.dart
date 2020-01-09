// Copyright (c) 2015, 2016, 2017, Hoylen Sue. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

library crypt.example;

import 'package:crypt/crypt.dart';

void main() {
  final c1 = Crypt.sha256('p@ssw0rd'); // default rounds, random salt
  final c2 = Crypt.sha256('p@ssw0rd', rounds: 10000); // random salt
  final c3 =
      Crypt.sha256('p@ssw0rd', salt: 'abcdefghijklmnop'); // default rounds
  final c4 = Crypt.sha256('p@ssw0rd', rounds: 10000, salt: 'abcdefghijklmnop');

  print(c1.toString());
  print(c2.toString());
  print(c3.toString());
  print(c4.toString());

  var suppliedValue = 'p@ssw0rd';
  if (c1.match(suppliedValue)) {
    print('Correct value match');
  } else {
    print('Error: unexpected non-match: $suppliedValue');
  }

  suppliedValue = '123456';
  if (c1.match(suppliedValue)) {
    print('Error: unexpected match: $suppliedValue');
  } else {
    print('Incorrect value does not match');
  }
}
