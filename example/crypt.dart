// Copyright (c) 2015, Hoylen Sue. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

library crypt.example;

import 'package:crypt/crypt.dart';

main() {
  var hash1 = Util_Crypt.sha256("p@ssw0rd"); // default rounds, random salt
  var hash2 = Util_Crypt.sha256("p@ssw0rd", rounds: 10000); // random salt
  var hash3 = Util_Crypt.sha256("p@ssw0rd", salt: "abcdefghijklmnop");
  var hash4 =
      Util_Crypt.sha256("p@ssw0rd", rounds: 10000, salt: "abcdefghijklmnop");

  print("SHA-256:");
  print(hash1);
  print(hash2);
  print(hash3);
  print(hash4);
}

//EOF
