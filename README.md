# crypt

One-way string hashing for salted passwords.

Implements the SHA-256 hash as specified by "[Unix crypt using SHA-256
and SHA-512][crypt-sha2]" (version: 0.4 2008-04-03).

Produces hash values like:

    $5$xYWYo0raYwLSchAd$na8cL1H.ESWtof6DNwraE6p8WI9DYObZ3irMe01Guk6
    $5$rounds=10000$saltstringsaltst$3xv.VbSHBb41AL9AvLeujZkZRBAwqFMz2.opqey6IcA

The $5$ indicates this is a SHA-256 format crypt. It is followed
the number of rounds (if the default of 5000 is not being used), the
salt and the hash.

## Usage

A simple usage example:

    import 'package:crypt/crypt.dart';

    main() {
      var hash1 = Crypt.sha256("p@ssw0rd"); // default rounds, random salt
      var hash2 = Crypt.sha256("p@ssw0rd", rounds: 10000); // random salt
      var hash3 = Crypt.sha256("p@ssw0rd", salt: "abcdefghijklmnop");
      var hash4 = Crypt.sha256("p@ssw0rd", rounds: 10000, salt:"abcdefghijklmnop");

      print(hash1);
      print(hash2);
      print(hash3);
      print(hash4);
    }

## Features and bugs

Currently only SHA-256 has been implemented.

Salt generation does not use a cryptographically secure random number
generator.

Please file feature requests and bugs at the [GitHub issue tracker][tracker].

[crypt-sha2]: http://www.akkadia.org/drepper/SHA-crypt.txt
[tracker]: https://github.com/hoylen/dart-crypt/issues
