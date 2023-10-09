# Changelog

## 4.3.1

- Upgraded to lint 2.1.1.

## 4.3.0

- Added check to reject a caller provided salt that contain a dollar sign.

## 4.2.1

- Improved documentation.

## 4.2.0

- Fixed changing cryptographicallySecureSalts after first salt generated.

## 4.1.0

- Use a cryptographically secure random number to generate salts,
  if one is available. Added `cryptographicallySecureSalts` to
  control whether a cryptographically insecure random number
  generator can be used if a cryptographically secure one is
  not supported.

## 4.0.1

- Fixed code formatting.

## 4.0.0

- Null safety release.

## 3.0.1

- Fixed URL in README.

## 3.0.0

- Added support for SHA-512 (which requires upgrading to crypto 2.1.0 or later).

## 2.0.0

- Code clean up to satisfy pana 0.13.2 health checks.
- Updated minimum dependency to Dart 2.3.

## 1.0.7

- Added hashCode property.
- Fixed dartanalyzer warnings.

## 1.0.6

- Updated the upper bound of the SDK constraint to <3.0.0.

## 1.0.5

- Code made sound to support Dart strong mode.

## 1.0.4

- Updated dependency to allow usage of crypto verson 2.0.2.

## 1.0.3

- Make compatible with Angular 2 version 3.1.

## 1.0.2

- Fixed parsing bug.

## 1.0.1

- Co-exist with other packages that depend on version 0.x.x of crypto.

## 1.0.0

- Match method and equality operator added.
- Changed to represent the crypt as an object with a toString method.

## 0.0.1

- Initial release.
