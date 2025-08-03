# API Reference: jwt.sign() and jwt.signSync()

Creates a JSON Web Token string by signing a payload with a secret or private key. Available in both asynchronous (Promise/callback) and synchronous versions.

## Syntax

### Asynchronous (Promise)
```typescript
jwt.sign(payload: string | Buffer | object, secretOrPrivateKey: Secret | PrivateKey, options?: SignOptions): Promise<string>
```

### Asynchronous (Callback)
```typescript
jwt.sign(payload: string | Buffer | object, secretOrPrivateKey: Secret | PrivateKey, callback: SignCallback): void
jwt.sign(payload: string | Buffer | object, secretOrPrivateKey: Secret | PrivateKey, options: SignOptions, callback: SignCallback): void
```

### Synchronous
```typescript
jwt.signSync(payload: string | Buffer | object, secretOrPrivateKey: Secret | PrivateKey, options?: SignOptions): string
```

## Parameters

### `payload`
The data to be encoded in the JWT. Can be:
- **Object literal** - Will be JSON stringified (recommended)
- **String** - Used as-is (must be valid JSON)
- **Buffer** - Used as-is

> **Note:** Claims like `exp`, `nbf`, `iat` are only automatically handled when payload is an object literal.

### `secretOrPrivateKey`
The key used to sign the token:
- **String** - UTF-8 encoded secret for HMAC algorithms
- **Buffer** - Secret for HMAC algorithms
- **KeyObject** - Private key for RSA/ECDSA algorithms
- **Object** - `{ key, passphrase }` for encrypted private keys

### `options` (optional)
Configuration object with the following properties:

#### Signing Options

| Option | Type | Description |
|--------|------|-------------|
| `algorithm` | `string` | Algorithm to use (default: `HS256`) |
| `expiresIn` | `string \| number` | Token expiration time |
| `notBefore` | `string \| number` | Token not valid before time |
| `audience` | `string \| string[]` | Token audience |
| `issuer` | `string` | Token issuer |
| `jwtid` | `string` | JWT ID |
| `subject` | `string` | Token subject |
| `noTimestamp` | `boolean` | Omit `iat` claim |
| `header` | `object` | Custom header fields |
| `keyid` | `string` | Key ID hint |
| `mutatePayload` | `boolean` | Modify payload object directly |
| `allowInsecureKeySizes` | `boolean` | Allow RSA keys < 2048 bits |
| `allowInvalidAsymmetricKeyTypes` | `boolean` | Allow mismatched key types |
| `allowInsecureNoneAlgorithm` | `boolean` | Enable 'none' algorithm |

## Return Value

- **Asynchronous (Promise)**: Returns a `Promise<string>` that resolves to the JWT string
- **Asynchronous (Callback)**: Calls the callback with `(err, token)` where token is the JWT string
- **Synchronous**: Returns the JWT string directly

## Examples

### Basic HMAC Signing

```javascript
const jwt = require('jsonwebtoken');

// Asynchronous (Promise)
const token = await jwt.sign({ userId: 123 }, 'secret');

// Asynchronous (Callback)
jwt.sign({ userId: 123 }, 'secret', (err, token) => {
  if (err) throw err;
  console.log(token);
});

// Synchronous
const token = jwt.signSync({ userId: 123 }, 'secret');

// With expiration (all methods)
const token = await jwt.sign(
  { userId: 123, email: 'user@example.com' }, 
  'secret',
  { expiresIn: '1h' }
);
```

### RSA Signing

```javascript
const fs = require('fs');
const privateKey = fs.readFileSync('private.key');

// Asynchronous
const token = await jwt.sign(
  { userId: 123 }, 
  privateKey,
  { algorithm: 'RS256' }
);

// Synchronous
const token = jwt.signSync(
  { userId: 123 }, 
  privateKey,
  { algorithm: 'RS256' }
);
```

### Using Encrypted Private Key

```javascript
const privateKey = fs.readFileSync('encrypted-private.key');

const token = await jwt.sign(
  { userId: 123 },
  { key: privateKey, passphrase: 'your-passphrase' },
  { algorithm: 'RS256' }
);
```

### Custom Headers

```javascript
const token = await jwt.sign(
  { userId: 123 },
  'secret',
  {
    header: {
      kid: '2024-01-01',
      typ: 'JWT'
    }
  }
);
```

### Time Spans

The `expiresIn` and `notBefore` options accept:
- **Number**: Seconds from now
- **String**: Time span using [vercel/ms](https://github.com/vercel/ms) format

```javascript
// Expires in 1 hour
await jwt.sign(payload, secret, { expiresIn: 60 * 60 });
await jwt.sign(payload, secret, { expiresIn: '1h' });

// Expires in 2 days
await jwt.sign(payload, secret, { expiresIn: '2 days' });

// Not valid before 10 minutes from now
await jwt.sign(payload, secret, { notBefore: '10m' });
```

### Manual Expiration

You can also set expiration directly in the payload:

```javascript
const token = await jwt.sign({
  userId: 123,
  exp: Math.floor(Date.now() / 1000) + (60 * 60) // 1 hour
}, 'secret');
```

### TypeScript Usage

```typescript
import jwt, { SignOptions, Algorithm, SignCallback } from 'jsonwebtoken';

interface TokenPayload {
  userId: number;
  role: string;
}

const payload: TokenPayload = {
  userId: 123,
  role: 'admin'
};

const options: SignOptions = {
  algorithm: 'RS256' as Algorithm,
  expiresIn: '24h',
  issuer: 'api.example.com'
};

// Asynchronous (Promise)
const token: string = await jwt.sign(payload, privateKey, options);

// Asynchronous (Callback)
jwt.sign(payload, privateKey, options, (err: Error | null, token?: string) => {
  if (err) throw err;
  console.log(token);
});

// Synchronous
const token: string = jwt.signSync(payload, privateKey, options);
```

## Error Handling

The `sign` methods will throw/reject with an error if:
- Invalid options are provided
- Key is invalid for the specified algorithm
- Key size is too small (RSA < 2048 bits without `allowInsecureKeySizes`)

### Asynchronous Error Handling
```javascript
// Promise
try {
  const token = await jwt.sign({ userId: 123 }, 'secret', {
    algorithm: 'invalid-algorithm'
  });
} catch (error) {
  console.error('Signing failed:', error.message);
}

// Callback
jwt.sign({ userId: 123 }, 'secret', { algorithm: 'invalid' }, (err, token) => {
  if (err) {
    console.error('Signing failed:', err.message);
  }
});
```

### Synchronous Error Handling
```javascript
try {
  const token = jwt.signSync({ userId: 123 }, 'secret', {
    algorithm: 'invalid-algorithm'
  });
} catch (error) {
  console.error('Signing failed:', error.message);
}
```

## Security Considerations

1. **Secret Storage**: Never hardcode secrets. Use environment variables:
   ```javascript
   const secret = process.env.JWT_SECRET;
   ```

2. **Key Size**: RSA keys must be at least 2048 bits unless `allowInsecureKeySizes` is true

3. **Algorithm Selection**: 
   - Use `RS256` or `ES256` for public/private key pairs
   - Use `HS256` for shared secrets
   - Never use `none` in production

4. **Expiration**: Always set token expiration for security:
   ```javascript
   await jwt.sign(payload, secret, { expiresIn: '15m' });
   ```

## Common Patterns

### Short-lived Access Tokens
```javascript
const accessToken = await jwt.sign(
  { userId: user.id, type: 'access' },
  secret,
  { expiresIn: '15m' }
);
```

### Long-lived Refresh Tokens
```javascript
const refreshToken = await jwt.sign(
  { userId: user.id, type: 'refresh' },
  secret,
  { expiresIn: '7d' }
);
```

### Including Multiple Claims
```javascript
const token = await jwt.sign({
  // Custom claims
  userId: 123,
  permissions: ['read', 'write'],
  
  // Standard claims (will be validated)
  iss: 'api.example.com',
  aud: 'mobile-app',
  sub: 'user:123'
}, secret, {
  expiresIn: '1h',
  jwtid: crypto.randomUUID()
});
```

## Choosing Between Async and Sync

- **Use async (`jwt.sign()`)** when:
  - Working in an async/await context
  - You want non-blocking operations
  - You're already using Promises in your application
  - You need better performance in high-concurrency scenarios

- **Use sync (`jwt.signSync()`)** when:
  - Working in a synchronous context
  - Simplicity is preferred over performance
  - You're in a script or CLI tool where blocking is acceptable

## See Also

- [jwt.verify() and jwt.verifySync()](API-Reference-verify) - Verify and decode tokens
- [jwt.decode()](API-Reference-decode) - Decode without verification
- [Usage Examples](Usage-Examples) - More examples
- [Security & Algorithms](Security-&-Algorithms) - Algorithm details