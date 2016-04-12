// Copyright (c) 2015, 2016, Hoylen Sue. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

library crypt.base;

import 'dart:math';
import 'package:crypto/crypto.dart' as Crypto;

//----------------------------------------------------------------
/// One-way string hashing for salted passwords using the Unix crypt format.
///
/// This class implements the SHA-256 crypt hash as specified by "[Unix crypt
/// using SHA-256 and SHA-512](http://www.akkadia.org/drepper/SHA-crypt.txt)"
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
  static const int _MAX_SHA_SALT_LENGTH = 16;
  static const String _SALT_CHARS =
      "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

  static const int _MIN_SHA_ROUNDS = 1000;

  // from the specification: do not change
  static const int _MAX_SHA_ROUNDS = 999999999;

  // from the specification: do not change

  static const int _DEFAULT_SHA_ROUNDS = 5000;

  // Random number generator used for generating salts

  static var _rnd = new Random();

  // from the specification: do not change
  /*
  static const String ID_MD5 = "1";
  static const String ID_BLOWFISH = "2a";
  static const String ID_SUN_MD5 = "md5";
  */
  static const String ID_SHA256 = "5";
  //static const String ID_SHA512 = "6";

  //----------------------------------------------------------------

  /// Algorithm used by the crypt.
  ///
  /// Allowed values: [TYPE_SHA256].

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

  bool operator ==(Crypt that) {
    if (this._type == that._type) {
      var defaultRounds;
      switch (this._type) {
        case ID_SHA256:
          defaultRounds = _DEFAULT_SHA_ROUNDS;
          break;
        default:
          return false;
      }
      var r1 = this._rounds ?? defaultRounds;
      var r2 = that._rounds ?? defaultRounds;

      return (r1 == r2 && this._salt == that._salt && this._hash == that._hash);
    }
    return false;
  }

  //----------------------------------------------------------------
  /// Constructor from a crypt format string.
  ///
  /// Produce a [Crypt] object from parsing a crypt format string.
  ///
  /// Throws [FormatException] or [RangeError] if the crypt format string is
  /// incorrect.

  Crypt(String cryptFormatStr) {
    var parts = cryptFormatStr.split(r"$");
    if ((parts.length == 4 || parts.length == 5) && parts[0].isEmpty) {
      _type = parts[1];

      if (_type == ID_SHA256) {
        // SHA-256

        // Get the rounds (if any)

        if (parts.length == 5) {
          // Parse explicitly specified rounds
          var roundsStr = "rounds=";
          if (!parts[2].startsWith(roundsStr)) {
            throw new FormatException(
                "Crypt string invalid: rounds: ${parts[2]}");
          }
          try {
            _rounds = int.parse(parts[2].substring(roundsStr.length));
          } on FormatException catch (_) {
            throw new FormatException(
                "Crypt string invalid: rounds: ${parts[2]}");
          }
          if (_rounds < _MIN_SHA_ROUNDS || _MAX_SHA_ROUNDS < _rounds) {
            throw new RangeError(
                "Crypt string rounds out of range: ${_rounds}");
          }
        } else {
          _rounds = null; // default rounds
        }

        // Get the salt

        _salt = parts[parts.length - 2];
        if (_MAX_SHA_SALT_LENGTH < salt.length) {
          throw new FormatException("Crypt string unexpected salt length");
        }

        // Get the hash

        _hash = parts[parts.length];
        if (_hash.length != 40) {
          throw new FormatException("Crypt string unexpected hash length");
        }
      } else {
        throw new FormatException(
            "Crypt string: unsupported algorithm: ${parts[1]}");
      }
    } else {
      throw new FormatException("Crypt string: invalid format");
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
    if (key == null) {
      key = ""; // to avoid raising an error
    }

    var value_bytes = new List<int>.from(key.codeUnits);

    // Determine the number of rounds to use

    var rounds_is_custom;
    if (rounds == null) {
      rounds_is_custom = false;
      rounds = _DEFAULT_SHA_ROUNDS;
    } else {
      rounds_is_custom = true;
      if (rounds < _MIN_SHA_ROUNDS) {
        rounds = _MIN_SHA_ROUNDS;
      } else if (_MAX_SHA_ROUNDS < rounds) {
        rounds = _MAX_SHA_ROUNDS;
      }
    }

    // Obtain salt to use

    var salt_bytes;
    if (salt == null) {
      // Generate a random 16-character salt
      salt_bytes = new List<int>();
      for (var x = 0; x < _MAX_SHA_SALT_LENGTH; x++) {
        salt_bytes
            .add(_SALT_CHARS.codeUnitAt(_rnd.nextInt(_SALT_CHARS.length)));
      }
      salt = new String.fromCharCodes(salt_bytes);
    } else {
      // Use provided salt (up to the maximum required length)
      if (_MAX_SHA_SALT_LENGTH < salt.length) {
        salt = salt.substring(0, _MAX_SHA_SALT_LENGTH);
      }
      salt_bytes = new List<int>.from(salt.codeUnits);
    }

    // Calculations
    //
    // The steps below refer to the numbered steps from the specification.

    List<int> data_a = []; // Step 1
    data_a.addAll(value_bytes); // Step 2
    data_a.addAll(salt_bytes); // Step 3

    List<int> data_b = []; // Step 4
    data_b.addAll(value_bytes); // Step 5
    data_b.addAll(salt_bytes); // Step 6
    data_b.addAll(value_bytes); // Step 7
    var alt_bytes = Crypto.sha256.convert(data_b).bytes; // Step 8

    var count = key.length;
    while (32 <= count) {
      data_a.addAll(alt_bytes);
      count -= 32;
    }
    if (0 < count) {
      data_a.addAll(alt_bytes.sublist(0, count)); // Step 10
    }

    // Step 11

    for (var bits = key.length; bits != 0; bits >>= 1) {
      if (bits & 0x01 != 0) {
        data_a.addAll(alt_bytes);
      } else {
        data_a.addAll(value_bytes);
      }
    }

    var digest_a_bytes = Crypto.sha256.convert(data_a).bytes; // Step 12

    var data_dp = []; // Step 13
    for (int x = 0; x < key.length; x++) {
      data_dp.addAll(value_bytes); // Step 14
    }
    var dp_bytes = Crypto.sha256.convert(data_dp).bytes; // Step 15

    // Step 16

    var p = new List<int>();

    count = key.length;
    while (32 <= count) {
      p.addAll(dp_bytes);
      count -= 32;
    }
    if (0 < count) {
      p.addAll(dp_bytes.sublist(0, count));
    }

    var data_ds = []; // Step 17
    var a0 = digest_a_bytes[0];
    assert(0 <= a0 && a0 < 256);
    for (int x = 0; x < 16 + a0; x++) {
      data_ds.addAll(salt_bytes);
    }
    var ds_bytes = Crypto.sha256.convert(data_ds).bytes; // Step 19

    // Step 20

    var s = new List<int>();

    count = salt.length;
    while (32 <= count) {
      s.addAll(ds_bytes);
      count -= 32;
    }
    if (0 < count) {
      s.addAll(ds_bytes.sublist(0, count));
    }

    // Step 21

    var running = digest_a_bytes;
    for (int r = 0; r < rounds; r++) {
      var data_c = [];

      if ((r % 2) == 1) {
        data_c.addAll(p);
      } else {
        data_c.addAll(running);
      }

      if ((r % 3) != 0) {
        data_c.addAll(s);
      }
      if ((r % 7) != 0) {
        data_c.addAll(p);
      }

      if ((r % 2) == 1) {
        data_c.addAll(running);
      } else {
        data_c.addAll(p);
      }

      running = Crypto.sha256.convert(data_c).bytes;
    }

    // Return the crypt formatted result

    var result = new StringBuffer();

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

    this._type = ID_SHA256;
    this._rounds = (rounds_is_custom) ? rounds : null;
    this._salt = salt;
    this._hash = result.toString();
  }

  static const String _64_ENCODING_CHARS =
      "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

  // Custom encoding of 3 bytes into 4 characters used by the SHA-256 crypt hash.

  static void _encode_3bytes(StringBuffer result, int b2, int b1, [int b0]) {
    var n;
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
      var value = w & 0x3F;
      result.write(_64_ENCODING_CHARS.substring(value, value + 1));
      w >>= 6;
    }
  }

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

  String toString() {
    var r = (_rounds != null) ? "rounds=$_rounds\$" : "";
    return "\$$_type\$$r$_salt\$$_hash";
  }

  //----------------------------------------------------------------
  /// Tests if a value hashes to the same hash.
  ///
  /// Returns true if the hash of the [value] matches this crypt hash. Otherwise
  /// false is returned.

  bool match(String value) {
    // Hash the value using the same parameters
    var that;
    switch (this._type) {
      case ID_SHA256:
        that = new Crypt.sha256(value, rounds: this._rounds, salt: this._salt);
        break;
      default:
        throw new StateError("Crypt: invalid algorithm: ${_type}");
    }

    // Compare the two
    return (this == that);
  }
}
