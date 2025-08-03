# jsonwebtoken

![Build Status](https://github.com/auth0/node-jsonwebtoken/workflows/CI/badge.svg)
[![npm version](https://badge.fury.io/js/jsonwebtoken.svg)](https://badge.fury.io/js/jsonwebtoken)
[![TypeScript](https://img.shields.io/badge/TypeScript-Ready-blue.svg)](https://www.typescriptlang.org/)
[![Coverage Status](https://coveralls.io/repos/github/auth0/node-jsonwebtoken/badge.svg?branch=master)](https://coveralls.io/github/auth0/node-jsonwebtoken?branch=master)

A TypeScript implementation of [JSON Web Tokens](https://tools.ietf.org/html/rfc7519) for Node.js.

## Installation

```bash
npm install jsonwebtoken
```

## Documentation

📚 **Complete documentation is available in the [docs](./docs) folder**

### API Reference
- [sign() - Create JWTs](./docs/API-Reference-sign.md)
- [verify() - Validate JWTs](./docs/API-Reference-verify.md)
- [decode() - Decode without verification](./docs/API-Reference-decode.md)
- [Synchronous API](./docs/API-Reference-Sync.md)

### Guides
- [Installation & Setup](./docs/Installation-&-Setup.md)
- [Migration Guide v10](./docs/Migration-Guide-v10.md)
- [Security & Algorithms](./docs/Security-&-Algorithms.md)

## Quick Start

### Asynchronous (Promise-based)
```javascript
const jwt = require('jsonwebtoken');

// Sign a token
const token = await jwt.sign({ foo: 'bar' }, 'secret');

// Verify a token
const decoded = await jwt.verify(token, 'secret');
console.log(decoded.foo) // 'bar'
```

### Synchronous
```javascript
const jwt = require('jsonwebtoken');

// Sign a token
const token = jwt.signSync({ foo: 'bar' }, 'secret');

// Verify a token
const decoded = jwt.verifySync(token, 'secret');
console.log(decoded.foo) // 'bar'
```

### Callback-based
```javascript
const jwt = require('jsonwebtoken');

// Sign a token
jwt.sign({ foo: 'bar' }, 'secret', (err, token) => {
  if (err) throw err;
  
  // Verify the token
  jwt.verify(token, 'secret', (err, decoded) => {
    if (err) throw err;
    console.log(decoded.foo) // 'bar'
  });
});
```

## Requirements

- **Node.js** >= 20
- **npm** >= 10

## License

This project is licensed under the MIT license. See the [LICENSE](LICENSE) file for more info.

## Author

[Auth0](https://auth0.com)

## Issue Reporting

If you have found a bug or if you have a feature request, please report them at this repository [issues section](https://github.com/auth0/node-jsonwebtoken/issues). Please do not report security vulnerabilities on the public GitHub issue tracker. The [Responsible Disclosure Program](https://auth0.com/whitehat) details the procedure for disclosing security issues.