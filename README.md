# crypt

One-way string hashing for salted passwords using the Unix crypt format.

This package implements the SHA-256 crypt hash and SHA-512 crypt hash,
as specified by "[Unix crypt using SHA-256 and SHA-512][crypt-sha2]"
(version: 0.6 2016-08-31).

## Crypt format strings

It can produce crypt formatted string like:

    $5$xYWYo0raYwLSchAd$na8cL1H.ESWtof6DNwraE6p8WI9DYObZ3irMe01Guk6

and

    $5$rounds=10000$saltstringsaltst$3xv.VbSHBb41AL9AvLeujZkZRBAwqFMz2.opqey6IcA

Where the leading "$5$" indicates this is a SHA-256 crypt, and is
followed a number of fields separated by the dollar sign: a optional
the number of rounds, the salt and the hash value. A leading "$6$"
indicates it is a SHA-512 crypt.

When SHA-256 or SHA-512 is being used, the default number of rounds is
5000 (as defined by the specification).

**Note:** different systems use the crypt formatted string
differently.  For example, as the value of the `userPassword`
attribute in an LDAP _posixAccount_ entry, "{crypt}" needs to be
prepended to it.

## Usage

```dart
import 'package:crypt/crypt.dart';

void main() {
  // Creating crypt strings

  // Default rounds and random salt generated
  final c1 = Crypt.sha256('p@ssw0rd');

  // Random salt generated
  final c2 = Crypt.sha256('p@ssw0rd', rounds: 10000);

  // Default rounds
  final c3 = Crypt.sha256('p@ssw0rd', salt: 'abcdefghijklmnop');

  // No defaults used
  final c4 = Crypt.sha256('p@ssw0rd', rounds: 10000,
                          salt: 'abcdefghijklmnop');

  // SHA-512
  final d1 = Crypt.sha512('p@ssw0rd');

  print(c1);
  print(c2);
  print(c3);
  print(c4);
  print(d1);

  // Comparing a value to a crypt hash

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

    final correctValue = 'p@ssw0rd';
    final wrongValue = '123456';

    if (!h.match(correctValue)) {
      print('Error: unexpected non-match: $correctValue');
    }

    if (h.match(wrongValue)) {
      print('Error: unexpected match: $wrongValue');
    }
  }
}
```

The above example produced the following output:

```
$5$jYq8PvB6hI3cLREQ$FGBjCL5NO1qSwync3LOlCWTnIBJCjVsFtst9jNnnBx9
$5$rounds=10000$wJiiNy1TwwaWhGFN$t2JsIqOgfXh/3LLQF.YA9XDlJmtpLYmSe4i9TZl7cM.
$5$abcdefghijklmnop$gUWLu9sDI2Qvs112Xb8jmgD3ySIRE5ek63jk6ybSs7D
$5$rounds=10000$abcdefghijklmnop$51muKIziT9VAyDZ2ZueAYvAwgIYx0cLxUCIAlPoWaHD
$6$LJgzW1oI9UZ5w8HO$pTL3hmFg2zBkQPqRhcej6CmY2Az0WLDVlnMGTg//71D3hDEvKCB7XqwtinHEM1rlD/YAlEjhy2Lb3LJQsNvXx.
```

## Features and bugs

Salt generation does not use a cryptographically secure random number
generator. If this is a concern, generate your own salt and pass it in
as one of the parameters.

Version 3.0.0 depends on the Dart [crypto][crypto] package, version
2.1.4 or newer, which has support for SHA-512.  If you need to use an
older version of _crypto_, use version 2.0.0 of this package -- but
that older version won't have support for SHA-512 crypt strings.

Please file feature requests and bugs at the [GitHub issue tracker][tracker].

[crypt-sha2]: https://akkadia.org/drepper/SHA-crypt.txt
[crypto]: https://pub.dartlang.org/packages/crypto
[tracker]: https://github.com/hoylen/dart-crypt/issues
