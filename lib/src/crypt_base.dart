// Copyright (c) 2015, 2016, Hoylen Sue. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

library crypt.base;

import 'dart:math';
import 'package:crypto/crypto.dart' as Crypto;

//----------------------------------------------------------------
/// One-way string hashing for salted passwords.
///
/// Use the [sha256] static method to hash a password.
///
/// For example:
///
///     import 'package:crypt/crypt.dart';
///
///     main() {
///       var hash1 = Crypt.sha256("p@ssw0rd"); // default rounds, random salt
///       var hash2 = Crypt.sha256("p@ssw0rd", rounds: 10000); // random salt
///       var hash3 = Crypt.sha256("p@ssw0rd", salt: "abcdefghijklmnop");
///       var hash4 = Crypt.sha256("p@ssw0rd", rounds: 10000, salt: "abcdefghijklmnop");
///
///       print(hash1);
///       print(hash2);
///       print(hash3);
///       print(hash4);
///     }
///
/// Note: some systems might expect the hash value in a different format.
/// For example, when used as the LDAP _userPassword_ attribute, it needs
/// to be prefaced with "{crypt}".
///
/// The [hashCode] method has nothing to do with the crypt hashes. It is
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

  // from the specification: do not change

  static var _rnd = new Random();

  //----------------------------------------------------------------
  /// Returns a hash of the key using SHA-256.
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

  static String sha256(String key, {int rounds, String salt}) {
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
    result.write(r"$5$");
    if (rounds_is_custom) {
      result.write("rounds=${rounds}\$");
    }
    result.write(salt);
    result.write("\$");

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

    return result.toString();
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

  //----------------------------------------------------------------
  /// Tests if a value hashes to the same hash.
  ///
  /// Returns true if the hash of the [value] matches the [hash], otherwise
  /// false.

  static bool compare(String hash, String value) {
    var parts = hash.split(r"$");
    if ((parts.length == 4 || parts.length == 5) && parts[0].isEmpty) {
      if (parts[1] == "5") {
        // SHA-256

        // Get the rounds (if any)

        var rounds; // null means uses default rounds
        if (parts.length == 5) {
          // Parse explicitly specified rounds
          var roundsStr = "rounds=";
          if (!parts[2].startsWith(roundsStr)) {
            return false; // bad syntax in rounds field
          }
          try {
            rounds = int.parse(parts[2].substring(roundsStr.length));
          } on FormatException catch (_) {
            return false;
          }
          if (rounds < _MIN_SHA_ROUNDS || _MAX_SHA_ROUNDS < rounds) {
            return false;
          }
        }

        // Get the salt

        var salt = parts[parts.length - 2];
        if (_MAX_SHA_SALT_LENGTH < salt.length) {
          return false; // onvalid salt length
        }

        // Compare

        var valueHash = Crypt.sha256(value, rounds: rounds, salt: salt);

        var match = true;
        for (var i = 0; i < min(hash.length, valueHash.length); i++) {
          if (hash.codeUnitAt(i) != valueHash.codeUnitAt(i)) {
            match = false; // do not break: constant time implementation
          }
        }

        return match;
      }
    }
    return false;
  }
}
