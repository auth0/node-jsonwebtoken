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

📚 **[View the complete documentation in our Wiki](https://github.com/auth0/node-jsonwebtoken/wiki)**

The Wiki includes:
- [Getting Started Guide](https://github.com/auth0/node-jsonwebtoken/wiki/Installation-&-Setup)
- [API Reference](https://github.com/auth0/node-jsonwebtoken/wiki)
- [Migration Guides](https://github.com/auth0/node-jsonwebtoken/wiki/Migration-Guide-v10)
- [TypeScript Examples](https://github.com/auth0/node-jsonwebtoken/wiki/Usage-Examples#typescript-examples)
- [Security Best Practices](https://github.com/auth0/node-jsonwebtoken/wiki/Security-&-Algorithms)

## Quick Start

```javascript
const jwt = require('jsonwebtoken');

// Sign a token
const token = await jwt.sign({ foo: 'bar' }, 'secret');

// Verify a token
const decoded = await jwt.verify(token, 'secret');
console.log(decoded.foo) // 'bar'
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