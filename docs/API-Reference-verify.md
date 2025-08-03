# API Reference: jwt.verify() and jwt.verifySync()

Verifies a JSON Web Token string and returns the decoded payload if the signature is valid. Available in both asynchronous (Promise/callback) and synchronous versions.

## Syntax

### Asynchronous (Promise)
```typescript
jwt.verify(token: string, secretOrPublicKey: Secret | PublicKey | GetPublicKeyOrSecret, options?: VerifyOptions): Promise<JwtPayload | string>
```

### Asynchronous (Callback)
```typescript
jwt.verify(token: string, secretOrPublicKey: Secret | PublicKey | GetPublicKeyOrSecret, callback: VerifyCallback): void
jwt.verify(token: string, secretOrPublicKey: Secret | PublicKey | GetPublicKeyOrSecret, options: VerifyOptions, callback: VerifyCallback): void
```

### Synchronous
```typescript
jwt.verifySync(token: string, secretOrPublicKey: Secret | PublicKey, options?: VerifyOptions): JwtPayload | string
```

> **Note:** `verifySync` does not support `GetPublicKeyOrSecret` (async key resolution functions) since it operates synchronously.

## Parameters

### `token`
The JWT string to verify.

### `secretOrPublicKey`
The key used to verify the token signature:
- **String** - UTF-8 encoded secret for HMAC algorithms
- **Buffer** - Secret for HMAC algorithms  
- **KeyObject** - Public key for RSA/ECDSA algorithms
- **Function** - Async function that returns the key (for dynamic key resolution)

### `options` (optional)
Configuration object with the following properties:

#### Verification Options

| Option | Type | Description |
|--------|------|-------------|
| `algorithms` | `string[]` | List of allowed algorithms |
| `audience` | `string \| RegExp \| (string\|RegExp)[]` | Expected audience |
| `complete` | `boolean` | Return an object with decoded header and payload |
| `issuer` | `string \| string[]` | Expected issuer |
| `jwtid` | `string` | Expected JWT ID |
| `ignoreExpiration` | `boolean` | Skip expiration check |
| `ignoreNotBefore` | `boolean` | Skip not-before check |
| `subject` | `string` | Expected subject |
| `clockTolerance` | `number` | Clock tolerance in seconds |
| `maxAge` | `string \| number` | Maximum token age |
| `clockTimestamp` | `number` | Time to use as current time (seconds) |
| `nonce` | `string` | Expected nonce value |
| `allowInvalidAsymmetricKeyTypes` | `boolean` | Allow mismatched key types |
| `allowInsecureKeySizes` | `boolean` | Allow RSA keys smaller than 2048 bits |

#### Header Validation Options (Security)

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `maxHeaderSize` | `number` | `8192` | Maximum JWT header size in bytes |
| `maxKidLength` | `number` | `1024` | Maximum length for `kid` header parameter |
| `kidCharacterWhitelist` | `RegExp` | `/^[\w\-._~]+$/` | Allowed characters in `kid` parameter |
| `disableHeaderValidation` | `boolean` | `false` | Disable all header security validation |

## Return Value

- **Asynchronous (Promise)**: Returns a `Promise` that resolves to:
  - **Decoded payload** (default) - The JWT payload as an object or string
  - **Complete JWT** (when `complete: true`) - Object with `{ header, payload, signature }`
- **Asynchronous (Callback)**: Calls the callback with `(err, decoded)` where decoded is the payload or complete JWT
- **Synchronous**: Returns the decoded payload or complete JWT directly

## Examples

### Basic Verification

```javascript
const jwt = require('jsonwebtoken');

// Asynchronous (Promise)
try {
  const decoded = await jwt.verify(token, 'secret');
  console.log(decoded); // { userId: 123, iat: 1516239022 }
} catch (err) {
  console.error('Invalid token');
}

// Asynchronous (Callback)
jwt.verify(token, 'secret', (err, decoded) => {
  if (err) {
    console.error('Invalid token');
  } else {
    console.log(decoded);
  }
});

// Synchronous
try {
  const decoded = jwt.verifySync(token, 'secret');
  console.log(decoded);
} catch (err) {
  console.error('Invalid token');
}
```

### RSA Public Key Verification

```javascript
const fs = require('fs');
const publicKey = fs.readFileSync('public.pem');

// Asynchronous
try {
  const decoded = await jwt.verify(token, publicKey);
  console.log(decoded);
} catch (err) {
  console.error('Invalid signature');
}

// Synchronous
try {
  const decoded = jwt.verifySync(token, publicKey);
  console.log(decoded);
} catch (err) {
  console.error('Invalid signature');
}
```

### Algorithm Validation

```javascript
try {
  // Only allow specific algorithms
  const decoded = await jwt.verify(token, publicKey, {
    algorithms: ['RS256', 'RS384']
  });
} catch (err) {
  if (err.message.includes('invalid signature')) {
    console.error('Algorithm mismatch');
  }
}
```

### Audience Validation

```javascript
// Single audience
const decoded = await jwt.verify(token, secret, {
  audience: 'urn:my-app'
});

// Multiple audiences
const decoded = await jwt.verify(token, secret, {
  audience: ['urn:my-app', 'urn:other-app']
});

// Regex pattern
const decoded = await jwt.verify(token, secret, {
  audience: /^urn:app:.+$/
});
```

### Complete Token Information

```javascript
const complete = await jwt.verify(token, secret, {
  complete: true
});

console.log(complete.header);    // { alg: 'HS256', typ: 'JWT' }
console.log(complete.payload);   // { userId: 123, ... }
console.log(complete.signature); // 'xyz...'
```

### Dynamic Key Resolution

```javascript
// Function that returns the appropriate key
async function getKey(header) {
  // Fetch key based on kid (key ID) in header
  const key = await fetchKeyFromDatabase(header.kid);
  return key;
}

// Only available with async verify
try {
  const decoded = await jwt.verify(token, getKey);
  console.log(decoded);
} catch (err) {
  console.error('Verification failed');
}

// Note: verifySync does NOT support dynamic key resolution
// This will throw an error:
// jwt.verifySync(token, getKey); // ❌ Error!
```

### Using with jwks-rsa

```javascript
const jwksClient = require('jwks-rsa');

const client = jwksClient({
  jwksUri: 'https://YOUR_DOMAIN/.well-known/jwks.json'
});

async function getKey(header) {
  const key = await client.getSigningKey(header.kid);
  return key.publicKey || key.rsaPublicKey;
}

const decoded = await jwt.verify(token, getKey);
```

### Header Validation (Security)

Protect against header injection attacks with configurable validation:

```javascript
// Default header validation (recommended)
const decoded = await jwt.verify(token, secret);

// Custom header size limit
const decoded = await jwt.verify(token, secret, {
  maxHeaderSize: 4096 // 4KB limit
});

// Strict kid validation
const decoded = await jwt.verify(token, secret, {
  maxKidLength: 256,
  kidCharacterWhitelist: /^[a-zA-Z0-9]+$/ // Only alphanumeric
});

// Disable validation (not recommended)
const decoded = await jwt.verify(token, secret, {
  disableHeaderValidation: true
});
```

**Note**: When using `GetPublicKeyOrSecret` callbacks, the header passed to your function is automatically sanitized to prevent injection attacks. Only standard JWT header fields are included, and the `kid` parameter is truncated to the configured maximum length.

### Clock Tolerance

Handle small time differences between servers:

```javascript
const decoded = await jwt.verify(token, secret, {
  clockTolerance: 60 // 60 seconds tolerance
});
```

### Maximum Age

Reject tokens older than specified age:

```javascript
const decoded = await jwt.verify(token, secret, {
  maxAge: '2h' // Token must be less than 2 hours old
});
```

### TypeScript Usage

```typescript
import jwt, { JwtPayload, VerifyOptions, VerifyCallback, GetPublicKeyOrSecret } from 'jsonwebtoken';

interface TokenPayload extends JwtPayload {
  userId: number;
  role: string;
}

const options: VerifyOptions = {
  algorithms: ['RS256'],
  audience: 'api.example.com',
  issuer: 'auth.example.com'
};

// Asynchronous (Promise)
try {
  const decoded = await jwt.verify(token, publicKey, options) as TokenPayload;
  console.log(decoded.userId); // Type-safe access
} catch (error) {
  if (error instanceof jwt.TokenExpiredError) {
    console.log('Token expired at:', error.expiredAt);
  } else if (error instanceof jwt.JsonWebTokenError) {
    console.log('Invalid token:', error.message);
  }
}

// Asynchronous (Callback)
jwt.verify(token, publicKey, options, (err, decoded) => {
  if (err) {
    console.error('Verification failed:', err);
  } else {
    const payload = decoded as TokenPayload;
    console.log(payload.userId);
  }
});

// Synchronous
try {
  const decoded = jwt.verifySync(token, publicKey, options) as TokenPayload;
  console.log(decoded.userId);
} catch (error) {
  console.error('Verification failed:', error);
}
```

## Error Handling

The `verify` method will reject with specific error types:

### TokenExpiredError
```javascript
try {
  const decoded = await jwt.verify(token, secret);
} catch (err) {
  if (err.name === 'TokenExpiredError') {
    console.log('Token expired at:', err.expiredAt);
  }
}
```

### JsonWebTokenError
```javascript
try {
  const decoded = await jwt.verify(token, secret);
} catch (err) {
  if (err.name === 'JsonWebTokenError') {
    // Could be: invalid signature, jwt malformed, etc.
    console.log('JWT Error:', err.message);
  }
}
```

### NotBeforeError
```javascript
try {
  const decoded = await jwt.verify(token, secret);
} catch (err) {
  if (err.name === 'NotBeforeError') {
    console.log('Token not active until:', err.date);
  }
}
```

## Security Considerations

1. **Algorithm Validation**: Always specify allowed algorithms:
   ```javascript
   await jwt.verify(token, key, { algorithms: ['RS256'] });
   ```

2. **Audience Validation**: Verify the token is for your application:
   ```javascript
   await jwt.verify(token, secret, { audience: 'your-app-id' });
   ```

3. **Issuer Validation**: Verify the token issuer:
   ```javascript
   await jwt.verify(token, secret, { issuer: 'trusted-issuer' });
   ```

4. **Base64 Secrets**: If using base64 encoded secrets:
   ```javascript
   const secret = Buffer.from(process.env.JWT_SECRET_BASE64, 'base64');
   const decoded = await jwt.verify(token, secret);
   ```

5. **Header Injection Protection**: The library automatically validates JWT headers to prevent injection attacks. Key features:
   - Path traversal detection in `kid` parameter
   - Character whitelisting for `kid` values
   - Header size limits to prevent DoS
   - Sanitized headers in `GetPublicKeyOrSecret` callbacks
   
   Configure validation based on your security requirements:
   ```javascript
   await jwt.verify(token, secret, {
     maxKidLength: 512,
     kidCharacterWhitelist: /^[a-zA-Z0-9\-_]+$/
   });
   ```

## Common Patterns

### Express Middleware
```javascript
// Async middleware (recommended)
async function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.sendStatus(401);
  }

  try {
    const user = await jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
    req.user = user;
    next();
  } catch (err) {
    return res.sendStatus(403);
  }
}

// Sync middleware (alternative)
function authenticateTokenSync(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.sendStatus(401);
  }

  try {
    const user = jwt.verifySync(token, process.env.ACCESS_TOKEN_SECRET);
    req.user = user;
    next();
  } catch (err) {
    return res.sendStatus(403);
  }
}
```

### Refresh Token Validation
```javascript
async function validateRefreshToken(token) {
  try {
    const decoded = await jwt.verify(token, process.env.REFRESH_TOKEN_SECRET, {
      audience: 'refresh',
      issuer: 'auth-service'
    });
    return decoded;
  } catch (err) {
    throw new Error('Invalid refresh token');
  }
}
```

### Multi-Tenant Validation
```javascript
async function verifyTenantToken(token, tenantId) {
  const decoded = await jwt.verify(token, secret, {
    audience: `tenant:${tenantId}`,
    issuer: 'multi-tenant-app'
  });
  return decoded;
}
```

## Choosing Between Async and Sync

- **Use async (`jwt.verify()`)** when:
  - Working with dynamic key resolution (`GetPublicKeyOrSecret`)
  - Working in an async/await context
  - Building web applications with async middleware
  - You need non-blocking operations
  - Better performance in high-concurrency scenarios

- **Use sync (`jwt.verifySync()`)** when:
  - Working in a synchronous context
  - Building CLI tools or scripts
  - Simplicity is preferred over performance
  - You don't need dynamic key resolution

## See Also

- [jwt.sign() and jwt.signSync()](API-Reference-sign) - Create tokens
- [jwt.decode()](API-Reference-decode) - Decode without verification
- [Error Reference](Error-Reference) - Error handling details
- [Security & Algorithms](Security-&-Algorithms) - Security best practices