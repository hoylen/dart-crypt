# crypt

One-way string hashing for salted passwords using the **Unix crypt format**.

This package implements the SHA-256 crypt hash and SHA-512 crypt hash,
cryptographic hash formats that are specified in
"[Unix crypt using SHA-256 and SHA-512][crypt-sha2]"
(version: 0.6 2016-08-31).

These hashes are commonly used in Unix and POSIX systems, and in LDAP
entries as authentication credentials for POSIX accounts.

## Crypt format strings

It can produce crypt formatted string like:

`$5$xYWYo0raYwLSchAd$na8cL1H.ESWtof6DNwraE6p8WI9DYObZ3irMe01Guk6`

and

`$5$rounds=10000$saltstringsaltst$3xv.VbSHBb41AL9AvLeujZkZRBAwqFMz2.opqey6IcA`

The format is a sequence of fields, leading and separated by a
dollar sign (`$`):

- algorithm indicator;
- number of rounds (optional if it is the default number of rounds);
- the salt; and
- the hash value.

The formated string starts with `$5$` for a SHA-256 crypt and `$6$`
for a SHA-512 crypt. There are other (less secure) algorithms, but
they are currently not supported by this package.

When SHA-256 or SHA-512 is being used, the default number of rounds is
5000 (as defined by the specification).

**Note:** different systems use the crypt formatted string
differently.  For example, as the value of the `userPassword`
attribute in an LDAP _posixAccount_ entry, `{crypt}` needs to be
prepended to it. For example,

`{crypt}$5$xYWYo0raYwLSchAd$na8cL1H.ESWtof6DNwraE6p8WI9DYObZ3irMe01Guk6`

## Usage

### Checking against a crypt format hash

To test if an entered password matches the password that was used to
create a crypt format hash, create a `Crypt` object from the crypt
format has and invoke the _match_ method on it.


```dart

bool isValid(String cryptFormatHash, String enteredPassword) =>
  Crypt(cryptFormatHash).match(enteredPassword);
```

### Generating a crypt format hash

To generate a crypt format hash, use `Crypt.sha256` or `Crypt.sha512`
constructors, and convert it to a String.

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
```

The above example produced the following output:

```text
$5$jYq8PvB6hI3cLREQ$FGBjCL5NO1qSwync3LOlCWTnIBJCjVsFtst9jNnnBx9
$5$rounds=10000$wJiiNy1TwwaWhGFN$t2JsIqOgfXh/3LLQF.YA9XDlJmtpLYmSe4i9TZl7cM.
$5$abcdefghijklmnop$gUWLu9sDI2Qvs112Xb8jmgD3ySIRE5ek63jk6ybSs7D
$5$rounds=10000$abcdefghijklmnop$51muKIziT9VAyDZ2ZueAYvAwgIYx0cLxUCIAlPoWaHD
$6$LJgzW1oI9UZ5w8HO$pTL3hmFg2zBkQPqRhcej6CmY2Az0WLDVlnMGTg//71D3hDEvKCB7XqwtinHEM1rlD/YAlEjhy2Lb3LJQsNvXx.
```

## Features and bugs

### Random number generators

Salt generation uses a cryptographically secure random number
generator, if one is available. If one is not available, it falls back
to using a cryptographically insecure one.

Set `Crypt.cryptographicallySecureSalts` to true to prevent a
cryptographically insecure random number from being used.  An
exception will then be thrown if attempting to generate a salt on
platforms that don't support a cryptographically secure random number
generator.

Explicitly set it to false to allow this fallback behaviour in future
releases. The default is currently set to false, for backward
compatibility. But a future release may set the default to true for
improved security. Explicitly setting it to false will ensure code
will still work when that breaking change is made.

### Dependency on the crypto package

The current release depends on the Dart [crypto][crypto] package
version 3.0.0, which has support for SHA-512.  If you need to use an
older version of _crypto_, use version 2.0.0 of this package -- but
that older version won't have support for SHA-512 crypt strings
and is not null safe.

Please file feature requests and bugs at the [GitHub issue tracker][tracker].

[crypt-sha2]: https://akkadia.org/drepper/SHA-crypt.txt
[crypto]: https://pub.dartlang.org/packages/crypto
[tracker]: https://github.com/hoylen/dart-crypt/issues
