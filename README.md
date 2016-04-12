# crypt

One-way string hashing for salted passwords using the Unix crypt format.

This package implements the SHA-256 crypt hash as specified by "[Unix
crypt using SHA-256 and SHA-512][crypt-sha2]" (version: 0.4
2008-04-03).

## Crypt format strings

It can produce crypt formatted string like:

    $5$xYWYo0raYwLSchAd$na8cL1H.ESWtof6DNwraE6p8WI9DYObZ3irMe01Guk6

and

    $5$rounds=10000$saltstringsaltst$3xv.VbSHBb41AL9AvLeujZkZRBAwqFMz2.opqey6IcA

Where the leading "$5$" indicates this is a SHA-256 crypt, and is
followed a number of fields separated by the dollar sign: a optional
the number of rounds, the salt and the hash value. When SHA-256 is
being used, the default number of rounds is 5000 (as defined by the
specification).

## Usage

```dart
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
```

The above example produced this output:

    $5$Uyh9BFrJI2eRkEch$3pgBGIfwTS/Twk1hI7o9Ev5c2cnBRtkwKEutg6.SLL9
    $5$rounds=10000$BRDqRDZxbDdvQSwP$74NE3FVcM79SNlzG.qmlM3xf6IIsdi8Qt8WJwVN60h8
    $5$abcdefghijklmnop$gUWLu9sDI2Qvs112Xb8jmgD3ySIRE5ek63jk6ybSs7D
    $5$rounds=10000$abcdefghijklmnop$51muKIziT9VAyDZ2ZueAYvAwgIYx0cLxUCIAlPoWaHD
    Correct value match
    Incorrect value does not match

Create a crypt from a value using the [sha256] constructor, or by
parsing a crypt formatted string using the default constructor.

Obtain the crypt formatted string by using the [toString] method.

Test if a value's hash matches using the [match] method.

## Features and bugs

Currently only SHA-256 crypt hashes are supported.  This package uses
the [crypto package][crypto] for the cryptographic algorithms, which
does not yet support DES or SHA-512. So those types of crypt hashes
are not supported.

Salt generation does not use a cryptographically secure random number
generator. If this is a concern, pass in a randomly generated salt
value that you want to use.

Please file feature requests and bugs at the [GitHub issue tracker][tracker].

[crypt-sha2]: http://www.akkadia.org/drepper/SHA-crypt.txt
[crypto]: https://pub.dartlang.org/packages/crypto
[tracker]: https://github.com/hoylen/dart-crypt/issues
