// Copyright (c) 2015, 2016, 2017, 2018, Hoylen Sue. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be found
// in the LICENSE file.

library crypt.base;

import 'dart:math';
import 'package:crypto/crypto.dart' as crypto;

//----------------------------------------------------------------
/// One-way string hashing for salted passwords using the Unix crypt format.
///
/// This class implements the SHA-256 crypt hash as specified by "Unix crypt
/// using SHA-256 and SHA-512 [ref](http://www.akkadia.org/drepper/SHA-crypt.txt)"
/// (version: 0.42008-04-03).
///
/// ## Usage
///
/// Construct a Crypt object using the [sha256] constructor or by parsing a
/// crypt format string using the default constructor.
///
/// The crypt format string value is obtained by using the [toString] method.
///
/// Test if a value's hash matches using the [match] method.
///
/// See <https://pub.dartlang.org/packages/crypt> for an example.
///
/// Note: The [hashCode] method has nothing to do with the crypt hashes. It is
/// inherited from the Dart object.

class Crypt {
  static const int _maxShaSaltLength = 16;
  static const String _saltChars =
      '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

  static const int _minShaRounds = 1000;

  // from the specification: do not change
  static const int _maxShaRounds = 999999999;

  // from the specification: do not change

  static const int _defaultShaRounds = 5000;

  // Random number generator used for generating salts

  static final _rnd = new Random();

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
  //static const String ID_SHA512 = '6';

  //----------------------------------------------------------------
  /// Constructor from a crypt format string.
  ///
  /// Produce a [Crypt] object from parsing a crypt format string.
  ///
  /// Throws [FormatException] or [RangeError] if the crypt format string is
  /// incorrect.

  Crypt(String cryptFormatStr) {
    final parts = cryptFormatStr.split(r'$');
    if ((parts.length == 4 || parts.length == 5) && parts[0].isEmpty) {
      _type = parts[1];

      if (_type == idSha256) {
        // SHA-256

        // Get the rounds (if any)

        if (parts.length == 5) {
          // Parse explicitly specified rounds
          final roundsStr = 'rounds=';
          if (!parts[2].startsWith(roundsStr)) {
            throw new FormatException(
                'Crypt string invalid rounds: ${parts[2]}');
          }
          try {
            _rounds = int.parse(parts[2].substring(roundsStr.length));
          } on FormatException catch (_) {
            throw new FormatException(
                'Crypt string invalid rounds: ${parts[2]}');
          }
          if (_rounds < _minShaRounds || _maxShaRounds < _rounds) {
            throw new RangeError('Crypt string rounds out of range: $_rounds');
          }
        } else {
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
          throw const FormatException('Crypt string is empty');
        }
      } else {
        throw new FormatException(
            'Crypt string: unsupported algorithm: ${parts[1]}');
      }
    } else {
      throw const FormatException('Crypt string invalid format');
    }
  }

  //----------------------------------------------------------------
  /// Constructor using the SHA-256 algorithm.
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
  /// generated hash.

  Crypt.sha256(String key, {int rounds, String salt}) {
    key ??= ''; // to avoid raising an error

    final valueBytes = new List<int>.from(key.codeUnits);

    // Determine the number of rounds to use

    bool customRounds;
    if (rounds == null) {
      customRounds = false;
      rounds = _defaultShaRounds;
    } else {
      customRounds = true;
      if (rounds < _minShaRounds) {
        rounds = _minShaRounds;
      } else if (_maxShaRounds < rounds) {
        rounds = _maxShaRounds;
      }
    }

    // Obtain salt to use

    List<int> saltBytes;
    if (salt == null) {
      // Generate a random 16-character salt
      saltBytes = <int>[];
      for (var x = 0; x < _maxShaSaltLength; x++) {
        saltBytes.add(_saltChars.codeUnitAt(_rnd.nextInt(_saltChars.length)));
      }
      salt = new String.fromCharCodes(saltBytes);
    } else {
      // Use provided salt (up to the maximum required length)
      if (_maxShaSaltLength < salt.length) {
        salt = salt.substring(0, _maxShaSaltLength);
      }
      saltBytes = new List<int>.from(salt.codeUnits);
    }

    // Calculations
    //
    // The steps below refer to the numbered steps from the specification.

    final dataA = <int>[] // Step 1
      ..addAll(valueBytes) // Step 2
      ..addAll(saltBytes); // Step 3

    final dataB = <int>[] // Step 4
      ..addAll(valueBytes) // Step 5
      ..addAll(saltBytes) // Step 6
      ..addAll(valueBytes); // Step 7
    final altBytes = crypto.sha256.convert(dataB).bytes; // Step 8

    var count = key.length;
    while (32 <= count) {
      dataA.addAll(altBytes);
      count -= 32;
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

    final digestA = crypto.sha256.convert(dataA).bytes; // Step 12

    final dataDP = <int>[]; // Step 13
    for (var x = 0; x < key.length; x++) {
      dataDP.addAll(valueBytes); // Step 14
    }
    final dpBytes = crypto.sha256.convert(dataDP).bytes; // Step 15

    // Step 16

    final p = <int>[];

    count = key.length;
    while (32 <= count) {
      p.addAll(dpBytes);
      count -= 32;
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
    final dsBytes = crypto.sha256.convert(dataDS).bytes; // Step 19

    // Step 20

    final s = <int>[];

    count = salt.length;
    while (32 <= count) {
      s.addAll(dsBytes);
      count -= 32;
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

      running = crypto.sha256.convert(dataC).bytes;
    }

    // Return the crypt formatted result

    final result = new StringBuffer();

    _encode_3bytes(result, running[0], running[10], running[20]);
    _encode_3bytes(result, running[21], running[1], running[11]);
    _encode_3bytes(result, running[12], running[22], running[2]);
    _encode_3bytes(result, running[3], running[13], running[23]);
    _encode_3bytes(result, running[24], running[4], running[14]);
    _encode_3bytes(result, running[15], running[25], running[5]);
    _encode_3bytes(result, running[6], running[16], running[26]);
    _encode_3bytes(result, running[27], running[7], running[17]);
    _encode_3bytes(result, running[18], running[28], running[8]);
    _encode_3bytes(result, running[9], running[19], running[29]);
    _encode_3bytes(result, running[31], running[30]);

    _type = idSha256;
    _rounds = (customRounds) ? rounds : null;
    _salt = salt;
    _hash = result.toString();
  }

  static const String _base64EncodingChars =
      './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

  // Custom encoding of 3 bytes into 4 characters used by the SHA-256 crypt hash.

  static void _encode_3bytes(StringBuffer result, int b2Input, int b1Input,
      [int b0Input]) {
    var b2 = b2Input;
    var b1 = b1Input;
    var b0 = b0Input;

    int n;
    if (b0 != null) {
      n = 4;
    } else {
      n = 3;
      b0 = b1;
      b1 = b2;
      b2 = 0;
    }

    var w = (b2 << 16) | (b1 << 8) | (b0);
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
  /// Allowed values: [idSha256].

  String get type => _type;
  String _type;

  /// Number of rounds or null.
  ///
  /// Null means the default number of rounds. When this is null, the number
  /// of rounds is not explicitly included in the crypt formatted string.

  int get rounds => _rounds;
  int _rounds;

  /// The salt value.

  String get salt => _salt;
  String _salt;

  /// The hash value.

  String get hash => _hash;
  String _hash;

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
          default:
            return false;
        }
        final r1 = _rounds ?? defaultRounds;
        final r2 = _rounds ?? defaultRounds;

        return (r1 == r2 && _salt == that._salt && _hash == that._hash);
      }
      return false;
    } else {
      return false;
    }
  }

  //----------------------------------------------------------------
  /// The hash code for this object.

  @override
  int get hashCode => (_hash != null) ? _hash.hashCode : 0;

  //================================================================

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
        that = new Crypt.sha256(value, rounds: _rounds, salt: _salt);
        break;
      default:
        throw new StateError('Crypt: invalid algorithm: $_type');
    }

    // Compare the two
    return (this == that);
  }
}
