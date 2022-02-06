// Copyright (c) 2015, 2016, 2017, 2018, 2020, 2022, Hoylen Sue.
// All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

library crypt.base;

import 'dart:math';
import 'package:crypto/crypto.dart' as crypto;

//################################################################
/// One-way string hashing for salted passwords using the Unix crypt format.
///
/// This class implements SHA-256 and SHA-512 crypt hashes as specified by
/// "[Unix crypt using SHA-256 and SHA-512](http://www.akkadia.org/drepper/SHA-crypt.txt)"
/// (version: 0.6 2016-08-31).
///
/// ## Usage
///
/// Construct a Crypt object using the [Crypt.sha256] or [Crypt.sha512]
/// constructors, or by parsing a crypt formatted string with the default
/// [Crypt] constructor.
///
/// The crypt format string value is obtained from a Crypt object by using its
/// [toString] method.
///
/// To test if a value matches a Crypt hash, create a Crypt object from the
/// crypt format string and then invoke the [match] method with the value
/// being tested.
///
/// The value of [cryptographicallySecureSalts] controls if the use of
/// non-cryptographically secure random number generators are allowed to be
/// used on platforms that do not have a cryptographically secure random number
/// generator. A random number generator is needed if random salts are needed
/// to be generated.
///
/// Note: The [hashCode] method has nothing to do with the crypt hashes. It is
/// a standard method in all Dart objects.

class Crypt {
  //================================================================
  // Constructors

  //----------------------------------------------------------------
  /// Creates a crypt from a crypt format string.
  ///
  /// Produce a [Crypt] object from parsing a crypt format string.
  ///
  /// Throws [FormatException] or [RangeError] if the crypt format string is
  /// incorrect.

  Crypt(String cryptFormatStr) {
    final parts = cryptFormatStr.split(r'$');
    if ((parts.length == 4 || parts.length == 5) && parts[0].isEmpty) {
      _type = parts[1];

      if (_type == idSha256 || _type == idSha512) {
        // SHA-256

        // Get the rounds (if any)

        if (parts.length == 5) {
          // Parse explicitly specified rounds
          const roundsStr = 'rounds=';
          if (!parts[2].startsWith(roundsStr)) {
            throw FormatException('Crypt string invalid rounds: ${parts[2]}');
          }
          try {
            final r = int.parse(parts[2].substring(roundsStr.length));
            if (r < _minShaRounds || _maxShaRounds < r) {
              throw RangeError('Crypt string rounds out of range: $r');
            }
            _rounds = r;
          } on FormatException catch (_) {
            throw FormatException('Crypt string invalid rounds: ${parts[2]}');
          }
        } else {
          // No explicit rounds specified
          _rounds = null; // default rounds
        }

        // Get the salt

        _salt = parts[parts.length - 2];
        if (_maxShaSaltLength < salt.length) {
          throw const FormatException('Crypt string unexpected salt length');
        }

        // Get the hash

        _hash = parts[parts.length - 1];
        if (_hash.isEmpty) {
          throw const FormatException('Crypt string empty hash');
        }
      } else {
        throw FormatException(
            'Crypt string: unsupported algorithm: ${parts[1]}');
      }
    } else {
      throw const FormatException('Crypt string invalid format');
    }
  }

  //----------------------------------------------------------------
  /// Creates a crypt using the SHA-256 algorithm.
  ///
  /// Implements the SHA-256 password hashing as specified by
  /// "Unix crypt using SHA-256 and SHA-512", by Ulrich Drepper,
  /// version: 0.4 2008-4-3.
  /// <http://www.akkadia.org/drepper/SHA-crypt.txt>
  ///
  /// The [key] is the value being hashed.
  ///
  /// If [rounds] is not provided, the default of 5000 is used and the rounds
  /// is not explicitly included in the result. Rounds less than 1000 results
  /// in 1000 being used. Rounds greater than 999,999,999 results in
  /// 999,999,999 being used. These numbers are defined by the specification.
  ///
  /// If the [salt] is not provided, a random 16-character salt is
  /// generated. Otherwise the provided value is used as the salt,
  /// up to 16 characters. If a longer salt is provided, the extra
  /// characters are ignored. Shorter salts (especially the empty string)
  /// are not recommended, since they reduce the security of the
  /// generated hash. An empty string is a valid salt, but obviously should
  /// not be used.
  ///
  /// Throws [UnsupportedError] if a cryptographically secure random number
  /// is required to generate the salt (i.e. [cryptographicallySecureSalts] is
  /// true) and it is not supported by the platform this is running on.

  Crypt.sha256(String key, {int? rounds, String? salt}) {
    final c = _sha251sha512Algorithm(crypto.sha256, 32, key,
        providedRounds: rounds, providedSalt: salt);

    final result = StringBuffer();

    _encode_3bytes(result, c[0], c[10], c[20]);
    _encode_3bytes(result, c[21], c[1], c[11]);
    _encode_3bytes(result, c[12], c[22], c[2]);
    _encode_3bytes(result, c[3], c[13], c[23]);
    _encode_3bytes(result, c[24], c[4], c[14]);
    _encode_3bytes(result, c[15], c[25], c[5]);
    _encode_3bytes(result, c[6], c[16], c[26]);
    _encode_3bytes(result, c[27], c[7], c[17]);
    _encode_3bytes(result, c[18], c[28], c[8]);
    _encode_3bytes(result, c[9], c[19], c[29]);
    _encode_3bytes(result, c[31], c[30]);

    _hash = result.toString();
    _type = idSha256;
  }

  //----------------------------------------------------------------
  /// Creates a crypt using the SHA-512 algorithm.
  ///
  /// Implements the SHA-512 password hashing as specified by
  /// "Unix crypt using SHA-256 and SHA-512", by Ulrich Drepper,
  /// version: 0.4 2008-4-3.
  /// <http://www.akkadia.org/drepper/SHA-crypt.txt>
  ///
  /// The [key] is the value being hashed.
  ///
  /// If [rounds] is not provided, the default of 5000 is used and the rounds
  /// is not explicitly included in the result. Rounds less than 1000 results
  /// in 1000 being used. Rounds greater than 999,999,999 results in
  /// 999,999,999 being used. These numbers are defined by the specification.
  ///
  /// If the [salt] is not provided, a random 16-character salt is
  /// generated. Otherwise the provided value is used as the salt,
  /// up to 16 characters. If a longer salt is provided, the extra
  /// characters are ignored. Shorter salts (especially the empty string)
  /// are not recommended, since they reduce the security of the
  /// generated hash. An empty string is a valid salt, but obviously should
  /// not be used.
  ///
  /// Throws [UnsupportedError] if a cryptographically secure random number
  /// is required to generate the salt (i.e. [cryptographicallySecureSalts] is
  /// true) and it is not supported by the platform this is running on.

  Crypt.sha512(String key, {int? rounds, String? salt}) {
    final c = _sha251sha512Algorithm(crypto.sha512, 64, key,
        providedRounds: rounds, providedSalt: salt);

    final result = StringBuffer();

    _encode_3bytes(result, c[0], c[21], c[42]);
    _encode_3bytes(result, c[22], c[43], c[1]);
    _encode_3bytes(result, c[44], c[2], c[23]);
    _encode_3bytes(result, c[3], c[24], c[45]);
    _encode_3bytes(result, c[25], c[46], c[4]);
    _encode_3bytes(result, c[47], c[5], c[26]);
    _encode_3bytes(result, c[6], c[27], c[48]);
    _encode_3bytes(result, c[28], c[49], c[7]);
    _encode_3bytes(result, c[50], c[8], c[29]);
    _encode_3bytes(result, c[9], c[30], c[51]);
    _encode_3bytes(result, c[31], c[52], c[10]);
    _encode_3bytes(result, c[53], c[11], c[32]);
    _encode_3bytes(result, c[12], c[33], c[54]);
    _encode_3bytes(result, c[34], c[55], c[13]);
    _encode_3bytes(result, c[56], c[14], c[35]);
    _encode_3bytes(result, c[15], c[36], c[57]);
    _encode_3bytes(result, c[37], c[58], c[16]);
    _encode_3bytes(result, c[59], c[17], c[38]);
    _encode_3bytes(result, c[18], c[39], c[60]);
    _encode_3bytes(result, c[40], c[61], c[19]);
    _encode_3bytes(result, c[62], c[20], c[41]);
    _encode_3bytes(result, c[63]);

    _hash = result.toString();
    _type = idSha512;
  }

  //================================================================
  // Constants

  static const int _maxShaSaltLength = 16;
  static const String _saltChars =
      '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

  static const int _minShaRounds = 1000;

  // from the specification: do not change
  static const int _maxShaRounds = 999999999;

  // from the specification: do not change

  static const int _defaultShaRounds = 5000;

  // from the specification: do not change
  /*
  /// Crypt ID for the MD5 (Linux, BSD) method.
  static const String ID_MD5 = '1';
  /// Crypt ID for the Blowfish (OpenBSD) method.
  static const String ID_BLOWFISH = '2a';
  /// Crypt ID for the Sun MD5 method.
  static const String ID_SUN_MD5 = 'md5';
  */

  /// Crypt ID for the SHA-256 method.
  static const String idSha256 = '5';

  // Crypt ID for the SHA-512 method.
  static const String idSha512 = '6';

  //================================================================
  // Static members

  //----------------------------------------------------------------
  /// Controls if non-cryptographically secure random salts are allowed.
  ///
  /// If no salt value is provided to [Crypt.sha256] and [Crypt.sha512], a
  /// salt is randomly generated. This member controls whether the random
  /// number generator can be non-cryptographically secure or not.
  ///
  /// If a cryptographically secure random number generator is available,
  /// it will always be used. This library will never uses a non-cryptographic
  /// secure one, if a cryptographically secure one is available. This member
  /// controls what happens if a cryptographically secure random number
  /// generator is not available: whether to allow fall back to a
  /// non-cryptographically secure random number generator or to fail.
  ///
  /// If set to false, it will fall back to using a non-cryptographically secure
  /// random number generator. This is less secure, but it will always be able
  /// to generate random salts---no matter what platform it is running on.
  ///
  /// If set to true, it will never fall back to using a non-cryptographically
  /// secure random number generator. If a cryptographically secure random
  /// number generator is not available, those constructors will throw an
  /// [UnsupportedError] exception. This is more secure, but the will not work
  /// on all platforms.
  ///
  /// This member only has effect on subsequently generated salts.
  /// Therefore, it should be set _before_ generating salts.
  ///
  /// **Recommendation:** Explicitly set the value instead of relying on the
  /// default value.
  ///
  /// The default is currently false, for backward compatibility with
  /// version 4.0.1 and earlier. Those versions always used a
  /// non-cryptographically secure random number generator.
  ///
  /// **A future release may make a breaking change** by setting the default
  /// to true. That will ensure better security by default, and programs that
  /// allow weaker salts must explicitly indicate that.
  /// On platforms without a cryptographically secure random number
  /// generator, that will cause programs that previously worked to fail.
  /// To prepare for that change, programs should **explicitly** set this
  /// to _false_, if it is acceptable to use a non-cryptographically secure
  /// random number generator to generate salts. That will ensure those program
  /// continue to work when the default is changed. The change will have no
  /// effect on platforms that have cryptographic secure random number
  /// generators.

  static bool cryptographicallySecureSalts = false;
  // TODO: change default to true to improve salt security: breaking change

  //----------------------------------------------------------------
  /// Random number generator used for generating salts
  ///
  /// Will be set on first invocation of [_generateSalt].

  static Random? _random;

  //----------------------------------------------------------------
  /// Indicates if [_random] is a secure random number generator or not.
  ///
  /// Will be set on first invocation of [_generateSalt].

  static late bool _randomIsSecure;

  //================================================================
  // Methods

  //----------------------------------------------------------------
  // Implementation of the algorithm used for SHA-256 and SHA-512 crypt.

  List<int> _sha251sha512Algorithm(
      crypto.Hash sha256sha512, int blockSize32or64, String key,
      {int? providedRounds, String? providedSalt}) {
    final valueBytes = List<int>.from(key.codeUnits);

    // Determine the number of rounds to use

    int rounds;
    bool customRounds;
    if (providedRounds == null) {
      customRounds = false;
      rounds = _defaultShaRounds;
    } else {
      customRounds = true;
      if (providedRounds < _minShaRounds) {
        rounds = _minShaRounds;
      } else if (_maxShaRounds < providedRounds) {
        rounds = _maxShaRounds;
      } else {
        rounds = providedRounds;
      }
    }

    // Obtain salt to use

    String salt;
    List<int> saltBytes;
    if (providedSalt == null) {
      // Generate a random 16-character salt: setting both saltBytes and salt
      saltBytes = _generateSalt(_maxShaSaltLength);
      salt = String.fromCharCodes(saltBytes);
    } else {
      // Use provided salt (truncated to the maximum required length)
      salt = (providedSalt.length <= _maxShaSaltLength)
          ? providedSalt
          : providedSalt.substring(0, _maxShaSaltLength);
      saltBytes = salt.codeUnits;
    }

    // Calculations
    //
    // The steps below refer to the numbered steps from the specification.

    final dataA = [
      // Step 1
      ...valueBytes, // Step 2
      ...saltBytes // Step 3
    ];

    final dataB = [
      // step 4
      ...valueBytes, // Step 5
      ...saltBytes, // Step 6
      ...valueBytes // Step 7
    ];

    final altBytes = sha256sha512.convert(dataB).bytes; // Step 8

    var count = key.length;
    while (blockSize32or64 <= count) {
      dataA.addAll(altBytes);
      count -= blockSize32or64;
    }
    if (0 < count) {
      dataA.addAll(altBytes.sublist(0, count)); // Step 10
    }

    // Step 11

    for (var bits = key.length; bits != 0; bits >>= 1) {
      if (bits & 0x01 != 0) {
        dataA.addAll(altBytes);
      } else {
        dataA.addAll(valueBytes);
      }
    }

    final digestA = sha256sha512.convert(dataA).bytes; // Step 12

    final dataDP = <int>[]; // Step 13
    for (var x = 0; x < key.length; x++) {
      dataDP.addAll(valueBytes); // Step 14
    }
    final dpBytes = sha256sha512.convert(dataDP).bytes; // Step 15

    // Step 16

    final p = <int>[];

    count = key.length;
    while (blockSize32or64 <= count) {
      p.addAll(dpBytes);
      count -= blockSize32or64;
    }
    if (0 < count) {
      p.addAll(dpBytes.sublist(0, count));
    }

    final dataDS = <int>[]; // Step 17
    final a0 = digestA[0];
    assert(0 <= a0 && a0 < 256);
    for (var x = 0; x < 16 + a0; x++) {
      dataDS.addAll(saltBytes);
    }
    final dsBytes = sha256sha512.convert(dataDS).bytes; // Step 19

    // Step 20

    final s = <int>[];

    count = salt.length;
    while (blockSize32or64 <= count) {
      s.addAll(dsBytes);
      count -= blockSize32or64;
    }
    if (0 < count) {
      s.addAll(dsBytes.sublist(0, count));
    }

    // Step 21

    var running = digestA;
    for (var r = 0; r < rounds; r++) {
      final dataC = <int>[];

      if ((r % 2) == 1) {
        dataC.addAll(p);
      } else {
        dataC.addAll(running);
      }

      if ((r % 3) != 0) {
        dataC.addAll(s);
      }
      if ((r % 7) != 0) {
        dataC.addAll(p);
      }

      if ((r % 2) == 1) {
        dataC.addAll(running);
      } else {
        dataC.addAll(p);
      }

      running = sha256sha512.convert(dataC).bytes;
    }

    _rounds = customRounds ? rounds : null;
    _salt = salt;

    return running;
  }

  //----------------------------------------------------------------

  static const String _base64EncodingChars =
      './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

  // Custom encoding of 3 bytes into 4 characters used by the SHA-256 and
  // SHA-512 crypt hash algorithm.
  //
  // When there are 3 bytes, the "third byte" is c, "second byte" is b and
  // "first byte" is a. And it results in 4 characters:
  //
  //     CCCCCCcc BBBBbbbb AAaaaaaa -> aaaaaa bbbbAA ccBBBBBB CCCCCC
  //
  // When used as the last group, only two or one bytes are avaliable and the
  // result is only three or two characters.
  //
  //     CCCCcccc BBbbbbbb -> bbbbbb ccccBB 0000CCCC
  //     CCcccccc -> cccccc 0000CC

  static void _encode_3bytes(StringBuffer result, int c, [int? b, int? a]) {
    int n; // number of characters in encoding
    int w; // 24-bit value with all the bytes in it

    // Note: if a is not null, b is never null

    if (a != null && b != null) {
      n = 4;
      w = (c << 16) | (b << 8) | a;
    } else if (b != null) {
      n = 3;
      w = (c << 8) | b;
    } else {
      n = 2;
      w = c;
    }

    while (0 < n--) {
      final value = w & 0x3F;
      result.write(_base64EncodingChars.substring(value, value + 1));
      w >>= 6;
    }
  }

  //================================================================
  // Operators

  //----------------------------------------------------------------

  /// Algorithm used by the crypt.
  ///
  /// Allowed values: [idSha256] or [idSha256].

  String get type => _type;
  late String _type;

  /// Number of rounds or null.
  ///
  /// Null means the default number of rounds. When this is null, the number
  /// of rounds is not explicitly included in the crypt formatted string,
  /// but its value is implied by the type.

  int? get rounds => _rounds;
  int? _rounds;

  /// The salt value.

  String get salt => _salt;
  late String _salt;

  /// The hash value.

  String get hash => _hash;
  late String _hash;

  //----------------------------------------------------------------
  /// Equality operator
  ///
  /// Returns true if both crypts are the same. That is, uses the same
  /// algorithm, the same rounds, the same salt and has the same hash.
  ///
  /// If one crypt uses the default number of rounds for the algorithm
  /// (i.e. [rounds] is null) and the other crypt explicitly specifies the
  /// number of rounds, the rounds are considered the same if their numeric
  /// values are the same.

  @override
  bool operator ==(Object that) {
    if (that is Crypt) {
      if (_type == that._type) {
        int defaultRounds;
        switch (_type) {
          case idSha256:
            defaultRounds = _defaultShaRounds;
            break;
          case idSha512:
            defaultRounds = _defaultShaRounds;
            break;
          default:
            // unknown or unsupported algorithm
            return false;
        }
        final r1 = _rounds ?? defaultRounds;
        final r2 = _rounds ?? defaultRounds;

        return r1 == r2 && _salt == that._salt && _hash == that._hash;
      }
      return false;
    } else {
      return false;
    }
  }

  //----------------------------------------------------------------
  /// The hash code for this object.

  @override
  int get hashCode => _hash.hashCode;

  //----------------------------------------------------------------
  /// Crypt format string.
  ///
  /// For example, returns a string like:
  ///
  ///     $5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5
  ///
  /// Note: some systems might expect the crypt format string to be represented
  /// slightly differently.  For example, when used as the LDAP _userPassword_
  /// attribute, it needs to be prepended with "{crypt}".

  @override
  String toString() {
    final r = (_rounds != null) ? 'rounds=$_rounds\$' : '';
    return '\$$_type\$$r$_salt\$$_hash';
  }

  //----------------------------------------------------------------
  /// Tests if a value hashes to the same hash.
  ///
  /// Returns true if the hash of the [value] matches this crypt hash. Otherwise
  /// false is returned.

  bool match(String value) {
    // Hash the value using the same parameters

    Crypt that;
    switch (_type) {
      case idSha256:
        that = Crypt.sha256(value, rounds: _rounds, salt: _salt);
        break;
      case idSha512:
        that = Crypt.sha512(value, rounds: _rounds, salt: _salt);
        break;
      default:
        throw StateError('Crypt: invalid algorithm: $_type');
    }

    // Compare the two
    return this == that;
  }

  //================================================================
  // Static methods

  //----------------------------------------------------------------
  /// Generate a random salt.
  ///
  /// The salt will be [length] randomly selected from the [_saltChars].
  ///
  /// Throws [UnsupportedError] if a cryptographically secure random number
  /// is required (i.e. [cryptographicallySecureSalts] is true) and it is
  /// not supported by the platform this is running on.

  static List<int> _generateSalt(int length) {
    if (_random == null) {
      // First use of the random number generator: instantiate it
      try {
        _random = Random.secure();
        _randomIsSecure = true;
      } on UnsupportedError {
        // Fallback
        _random = Random(); // a non-cryptographically secure generator
        _randomIsSecure = false;
      }
    }

    // Check suitability of the random number generator

    if (cryptographicallySecureSalts && !_randomIsSecure) {
      // Must be cryptographically secure, but one is not available
      throw UnsupportedError(
          'cryptographically secure random number generator unavailable'
          ': cannot generate salt'
          ': provide a salt value'
          ' or set Crypt.cryptographicallySecureSalts=false to allow the use'
          ' of a non-cryptographically secure random number generator.');
    }

    // Choose random characters

    final saltBytes = <int>[];
    for (var x = 0; x < length; x++) {
      saltBytes.add(_saltChars.codeUnitAt(_random!.nextInt(_saltChars.length)));
    }
    return saltBytes;
  }
}
