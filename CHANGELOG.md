# Change Log

All notable changes to this project will be documented in this file starting from version **v4.0.0**.
This project adheres to [Semantic Versioning](http://semver.org/).

## [4.1.0] - 2015-03-10
### Changed
- Assume the payload is JSON even when there is no `typ` property. [5290db1](https://github.com/auth0/node-jsonwebtoken/commit/5290db1bd74f74cd38c90b19e2355ef223a4d931)

## [4.0.0] - 2015-03-06
### Changed
- The default encoding is now utf8 instead of binary. [92d33bd](https://github.com/auth0/node-jsonwebtoken/commit/92d33bd99a3416e9e5a8897d9ad8ff7d70a00bfd)
- Add `encoding` as a new option to `sign`. [1fc385e](https://github.com/auth0/node-jsonwebtoken/commit/1fc385ee10bd0018cd1441552dce6c2e5a16375f)
- Add `ignoreExpiration` to `verify`. [8d4da27](https://github.com/auth0/node-jsonwebtoken/commit/8d4da279e1b351ac71ace276285c9255186d549f)
- Add `expiresInSeconds` to `sign`. [dd156cc](https://github.com/auth0/node-jsonwebtoken/commit/dd156cc30f17028744e60aec0502897e34609329)

### Fixed
- Fix wrong error message when the audience doesn't match. [44e3c8d](https://github.com/auth0/node-jsonwebtoken/commit/44e3c8d757e6b4e2a57a69a035f26b4abec3e327)
- Fix wrong error message when the issuer doesn't match. [44e3c8d](https://github.com/auth0/node-jsonwebtoken/commit/44e3c8d757e6b4e2a57a69a035f26b4abec3e327)
- Fix wrong `iat` and `exp` values when signing with `noTimestamp`. [331b7bc](https://github.com/auth0/node-jsonwebtoken/commit/331b7bc9cc335561f8806f2c4558e105cb53e0a6)