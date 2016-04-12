// Copyright (c) 2015, 2016, Hoylen Sue. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

library crypt.example;

import 'package:crypt/crypt.dart';

main() {
  var c1 = new Crypt.sha256("p@ssw0rd"); // default rounds, random salt
  var c2 = new Crypt.sha256("p@ssw0rd", rounds: 10000); // random salt
  var c3 = new Crypt.sha256("p@ssw0rd", salt: "abcdefghijklmnop"); // default rounds
  var c4 = new Crypt.sha256("p@ssw0rd", rounds: 10000, salt:"abcdefghijklmnop");

  print(c1.toString());
  print(c2.toString());
  print(c3.toString());
  print(c4.toString());

  var suppliedValue = "p@ssw0rd";
  if (c1.match(suppliedValue)) {
    print("Correct value match");
  } else {
    print("Error: unexpected non-match: $suppliedValue");
  }

  suppliedValue = "123456";
  if (c1.match(suppliedValue)) {
    print("Error: unexpected match: $suppliedValue");
  } else {
    print("Incorrect value does not match");
  }
}
