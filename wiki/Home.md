# Welcome to the jsonwebtoken Wiki

Welcome to the comprehensive documentation for the `jsonwebtoken` library - a TypeScript implementation of [JSON Web Tokens](https://tools.ietf.org/html/rfc7519) for Node.js.

## 📚 Documentation Structure

### Getting Started
- **[Installation & Setup](Installation-&-Setup)** - How to install and configure the library
- **[Quick Start Guide](Quick-Start)** - Get up and running in minutes

### Migration Guides
- **[v10.0.0 Breaking Changes](Migration-Guide-v10)** ⚠️ - Migrate from v9 to v10 (Promise-based API)
- **[v8 to v9 Migration](Migration-Notes-v8-to-v9)** - Previous migration guide
- **[v7 to v8 Migration](Migration-Notes-v7-to-v8)** - Previous migration guide

### API Reference
- **[jwt.sign()](API-Reference-sign)** - Create JSON Web Tokens
- **[jwt.verify()](API-Reference-verify)** - Validate and decode tokens
- **[jwt.decode()](API-Reference-decode)** - Decode without verification

### Examples & Guides
- **[Usage Examples](Usage-Examples)** - Common use cases and patterns
- **[TypeScript Examples](Usage-Examples#typescript-examples)** - Type-safe JWT handling
- **[Error Handling](Error-Reference)** - Handle JWT errors properly

### Security & Algorithms
- **[Supported Algorithms](Security-&-Algorithms)** - Algorithm reference and security warnings
- **[Security Best Practices](Security-&-Algorithms#best-practices)** - Keep your JWTs secure

### Advanced Topics
- **[Token Expiration Strategies](Advanced-Topics#token-expiration)** - Managing token lifetimes
- **[Refreshing JWTs](Advanced-Topics#refreshing-jwts)** - Token refresh patterns
- **[Dynamic Key Resolution](Advanced-Topics#dynamic-keys)** - Using key callbacks
- **[Custom Headers](Advanced-Topics#custom-headers)** - Adding custom JWT headers

## 🚀 What's New in v10

Version 10.0.0 brings major improvements:
- **Promise-based API** - Modern async/await support
- **TypeScript** - Complete rewrite in TypeScript
- **Better Performance** - Improved error handling and cleaner stack traces
- **Enhanced Security** - 'none' algorithm requires explicit opt-in

[Learn more about v10 changes →](Migration-Guide-v10)

## 💡 Quick Links

- [NPM Package](https://www.npmjs.com/package/jsonwebtoken)
- [GitHub Repository](https://github.com/auth0/node-jsonwebtoken)
- [Issue Tracker](https://github.com/auth0/node-jsonwebtoken/issues)
- [JWT.io](https://jwt.io) - JWT Debugger and Resources

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](https://github.com/auth0/node-jsonwebtoken/blob/master/CONTRIBUTING.md) for details.

## 📄 License

This project is licensed under the MIT license. See the [LICENSE](https://github.com/auth0/node-jsonwebtoken/blob/master/LICENSE) file for more info.