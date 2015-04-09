# dart-crypt

One-way string hashing for salted passwords.

Currently only the SHA-256 password hashing as specified by "[Unix
crypt using SHA-256 and SHA-512][crypt-sha2]" (version: 0.4
2008-04-03) is implemented.

[crypt-sha2]: http://www.akkadia.org/drepper/SHA-crypt.txt

Produces hash values like:

    $5$rounds=10000$saltstringsaltst$3xv.VbSHBb41AL9AvLeujZkZRBAwqFMz2.opqey6IcA

## Usage

A simple usage example:

    import 'package:crypt/crypt.dart';

    main() {
      var hash1 = Util_Crypt.sha256("p@ssw0rd"); // default rounds, random salt
      var hash2 = Util_Crypt.sha256("p@ssw0rd", rounds: 10000); // random salt
      var hash3 = Util_Crypt.sha256("p@ssw0rd", salt: "abcdefghijklmnop"); // default rounds
      var hash4 = Util_Crypt.sha256("p@ssw0rd", rounds: 10000, salt: "abcdefghijklmnop");

      print(hash1);
      print(hash2);
      print(hash3);
      print(hash4);
    }

## Features and bugs

Please file feature requests and bugs at the [GitHub issue tracker][tracker].

[tracker]: https://github.com/hoylen/dart-crypt/issues
