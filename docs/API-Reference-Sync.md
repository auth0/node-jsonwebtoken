# API Reference: Synchronous Methods

This page documents the synchronous versions of the JWT methods: `signSync()` and `verifySync()`.

## jwt.signSync()

Creates a JSON Web Token string synchronously.

### Syntax

```typescript
jwt.signSync(payload: string | Buffer | object, secretOrPrivateKey: Secret | PrivateKey, options?: SignOptions): string
```

### Parameters

Same as `jwt.sign()` - see [jwt.sign() documentation](API-Reference-sign#parameters).

### Return Value

Returns the JWT string directly (not a Promise).

### Example

```javascript
const jwt = require('jsonwebtoken');

// Synchronous signing
const token = jwt.signSync({ userId: 123 }, 'secret', { expiresIn: '1h' });
console.log(token);
```

## jwt.verifySync()

Verifies a JSON Web Token string synchronously.

### Syntax

```typescript
jwt.verifySync(token: string, secretOrPublicKey: Secret | PublicKey, options?: VerifyOptions): JwtPayload | string
```

### Parameters

Same as `jwt.verify()` with one important limitation:
- **Does NOT support** `GetPublicKeyOrSecret` (async key resolution functions)
- All other parameters are the same - see [jwt.verify() documentation](API-Reference-verify#parameters)

### Return Value

Returns the decoded payload directly (not a Promise).

### Example

```javascript
const jwt = require('jsonwebtoken');

try {
  // Synchronous verification
  const decoded = jwt.verifySync(token, 'secret');
  console.log(decoded);
} catch (err) {
  console.error('Invalid token:', err.message);
}
```

### Limitations

The synchronous verify method cannot use dynamic key resolution:

```javascript
// This will NOT work with verifySync
const getKey = async (header) => {
  return await fetchKeyFromDatabase(header.kid);
};

// This will throw an error
try {
  jwt.verifySync(token, getKey); // ❌ Error: Synchronous verify cannot use async key resolution
} catch (err) {
  console.error(err.message);
}
```

## When to Use Synchronous Methods

### Use Synchronous Methods When:
- Working in a synchronous context (scripts, CLI tools)
- Simplicity is more important than performance
- You don't need dynamic key resolution
- You're migrating from v9.x and want minimal code changes

### Avoid Synchronous Methods When:
- Building web servers or APIs (blocks the event loop)
- Working with dynamic key resolution
- Performance is critical
- You're already using async/await in your codebase

## Migration from v9.x

If you're migrating from v9.x and used the synchronous style (no callbacks), simply update your imports:

```javascript
// v9.x
const token = jwt.sign(payload, secret);
const decoded = jwt.verify(token, secret);

// v10.x
const token = jwt.signSync(payload, secret);
const decoded = jwt.verifySync(token, secret);
```

## Error Handling

Both synchronous methods throw errors directly:

```javascript
// signSync error handling
try {
  const token = jwt.signSync({ userId: 123 }, 'secret', {
    algorithm: 'invalid-algorithm'
  });
} catch (error) {
  console.error('Signing failed:', error.message);
}

// verifySync error handling
try {
  const decoded = jwt.verifySync(token, secret);
} catch (error) {
  if (error.name === 'TokenExpiredError') {
    console.log('Token expired at:', error.expiredAt);
  } else if (error.name === 'JsonWebTokenError') {
    console.log('Invalid token:', error.message);
  }
}
```

## See Also

- [jwt.sign() and jwt.signSync()](API-Reference-sign) - Full sign documentation
- [jwt.verify() and jwt.verifySync()](API-Reference-verify) - Full verify documentation
- [Migration Guide v10](Migration-Guide-v10) - Migrating from v9.x