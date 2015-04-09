// Copyright (c) 2015, Hoylen Sue. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

library crypt.base;

import 'dart:math';
import 'package:crypto/crypto.dart';

//----------------------------------------------------------------

class Util_Crypt {
  static const int MAX_SHA_SALT_LENGTH = 16;
  static const String SALT_CHARS =
      "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

  static const int MIN_SHA_ROUNDS =
      1000; // from the specification: do not change
  static const int MAX_SHA_ROUNDS =
      999999999; // from the specification: do not change

  static const int DEFAULT_SHA_ROUNDS =
      5000; // from the specification: do not change

  static var rnd = new Random();

  //----------------------------------------------------------------
  /// Returns the unix crypt using SHA-256
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
  /// 999,999,999 being used.
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
      rounds = DEFAULT_SHA_ROUNDS;
    } else {
      rounds_is_custom = true;
      if (rounds < MIN_SHA_ROUNDS) {
        rounds = MIN_SHA_ROUNDS;
      } else if (MAX_SHA_ROUNDS < rounds) {
        rounds = MAX_SHA_ROUNDS;
      }
    }

    // Obtain salt to use

    var salt_bytes;
    if (salt == null) {
      // Generate a random 16-character salt
      salt_bytes = new List<int>();
      for (var x = 0; x < MAX_SHA_SALT_LENGTH; x++) {
        salt_bytes.add(SALT_CHARS.codeUnitAt(rnd.nextInt(SALT_CHARS.length)));
      }
      salt = new String.fromCharCodes(salt_bytes);
    } else {
      // Use provided salt (up to the maximum required length)
      if (MAX_SHA_SALT_LENGTH < salt.length) {
        salt = salt.substring(0, MAX_SHA_SALT_LENGTH);
      }
      salt_bytes = new List<int>.from(salt.codeUnits);
    }

    // Calculations
    //
    // The steps below refer to the numbered steps from the specification.

    var digest_a = new SHA256(); // Step 1
    digest_a.add(value_bytes); // Step 2
    digest_a.add(salt_bytes); // Step 3

    var digest_b = new SHA256(); // Step 4
    digest_b.add(value_bytes); // Step 5
    digest_b.add(salt_bytes); // Step 6
    digest_b.add(value_bytes); // Step 7
    var alt_bytes = digest_b.close(); // Step 8

    var count = key.length;
    while (32 <= count) {
      digest_a.add(alt_bytes);
      count -= 32;
    }
    if (0 < count) {
      digest_a.add(alt_bytes.sublist(0, count)); // Step 10
    }

    // Step 11

    for (var bits = key.length; bits != 0; bits >>= 1) {
      if (bits & 0x01 != 0) {
        digest_a.add(alt_bytes);
      } else {
        digest_a.add(value_bytes);
      }
    }

    var digest_a_bytes = digest_a.close(); // Step 12

    var dp = new SHA256(); // Step 13
    for (int x = 0; x < key.length; x++) {
      dp.add(value_bytes); // Step 14
    }
    var dp_bytes = dp.close(); // Step 15

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

    var ds = new SHA256(); // Step 17
    var a0 = digest_a_bytes[0];
    assert(0 <= a0 && a0 < 256);
    for (int x = 0; x < 16 + a0; x++) {
      ds.add(salt_bytes);
    }
    var ds_bytes = ds.close(); // Step 19

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
      var c = new SHA256();

      if ((r % 2) == 1) {
        c.add(p);
      } else {
        c.add(running);
      }

      if ((r % 3) != 0) {
        c.add(s);
      }
      if ((r % 7) != 0) {
        c.add(p);
      }

      if ((r % 2) == 1) {
        c.add(running);
      } else {
        c.add(p);
      }

      running = c.close();
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
}

//EOF