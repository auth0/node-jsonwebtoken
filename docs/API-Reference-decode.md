# API Reference: jwt.decode()

Decodes a JSON Web Token without verifying its signature. This is useful when you need to inspect the token's contents but don't need cryptographic verification.

> **⚠️ Warning:** This method does **NOT** verify the token signature. Never use this for untrusted tokens or security-critical operations. Use [`jwt.verify()`](API-Reference-verify) instead for secure token validation.

## Syntax

```typescript
jwt.decode(token: string, options?: DecodeOptions): null | JwtPayload | string
```

## Parameters

### `token`
The JWT string to decode.

### `options` (optional)
Configuration object with the following properties:

| Option | Type | Description |
|--------|------|-------------|
| `complete` | `boolean` | Return complete token object with header and payload |
| `json` | `boolean` | Force JSON.parse on payload even if header doesn't contain `"typ":"JWT"` |

## Return Value

Returns:
- **Decoded payload** (default) - The JWT payload as an object or string
- **Complete token** (when `complete: true`) - Object with `{ header, payload, signature }`
- **`null`** - If the token is invalid or cannot be decoded

## Examples

### Basic Decoding

```javascript
const jwt = require('jsonwebtoken');

// Decode payload only
const decoded = jwt.decode(token);
console.log(decoded);
// Output: { userId: 123, iat: 1516239022, exp: 1516242622 }
```

### Complete Token Decoding

```javascript
// Get header, payload, and signature
const decoded = jwt.decode(token, { complete: true });

console.log(decoded.header);
// Output: { alg: 'HS256', typ: 'JWT' }

console.log(decoded.payload);
// Output: { userId: 123, iat: 1516239022 }

console.log(decoded.signature);
// Output: 'XbPfbIHMI6arZ3Y922BhjWgQzWXcXNrz0ogtVhfEd2o'
```

### Handling Invalid Tokens

```javascript
const token = 'invalid.token';
const decoded = jwt.decode(token);

if (decoded === null) {
  console.log('Failed to decode token');
}
```

### TypeScript Usage

```typescript
import jwt, { JwtPayload } from 'jsonwebtoken';

interface TokenPayload extends JwtPayload {
  userId: number;
  email: string;
}

// Decode with type assertion
const decoded = jwt.decode(token) as TokenPayload | null;

if (decoded) {
  console.log(decoded.userId); // Type-safe access
  console.log(decoded.email);
}

// Decode complete token
const complete = jwt.decode(token, { complete: true });
if (complete) {
  console.log(complete.header.alg); // Algorithm used
  console.log((complete.payload as TokenPayload).userId);
}
```

## Use Cases

### 1. Debugging and Inspection

```javascript
function inspectToken(token) {
  const decoded = jwt.decode(token, { complete: true });
  
  if (!decoded) {
    console.log('Invalid token format');
    return;
  }
  
  console.log('Algorithm:', decoded.header.alg);
  console.log('Type:', decoded.header.typ);
  console.log('Payload:', JSON.stringify(decoded.payload, null, 2));
  
  // Check expiration without verification
  if (decoded.payload.exp) {
    const expDate = new Date(decoded.payload.exp * 1000);
    console.log('Expires:', expDate);
    console.log('Expired:', expDate < new Date());
  }
}
```

### 2. Client-Side Token Reading

```javascript
// In a browser or non-secure context
function getUserIdFromToken(token) {
  const decoded = jwt.decode(token);
  return decoded?.userId || null;
}

// Display user info from token
function displayUserInfo(token) {
  const decoded = jwt.decode(token);
  
  if (decoded) {
    document.getElementById('username').textContent = decoded.username;
    document.getElementById('role').textContent = decoded.role;
  }
}
```

### 3. Token Routing

```javascript
// Route tokens to appropriate handlers based on content
function routeToken(token) {
  const decoded = jwt.decode(token, { complete: true });
  
  if (!decoded) {
    throw new Error('Invalid token');
  }
  
  // Route based on issuer
  switch (decoded.payload.iss) {
    case 'auth-service-a':
      return handleServiceAToken(token);
    case 'auth-service-b':
      return handleServiceBToken(token);
    default:
      throw new Error('Unknown token issuer');
  }
}
```

### 4. Pre-Verification Checks

```javascript
// Check token before expensive verification
async function processToken(token) {
  // Quick decode to check basic validity
  const decoded = jwt.decode(token);
  
  if (!decoded) {
    throw new Error('Malformed token');
  }
  
  // Check if token is expired before verification
  if (decoded.exp && decoded.exp < Date.now() / 1000) {
    throw new Error('Token already expired');
  }
  
  // Check if it's for our application
  if (decoded.aud !== 'our-app-id') {
    throw new Error('Token not for this application');
  }
  
  // Now do the expensive verification
  return await jwt.verify(token, secret);
}
```

## Security Warnings

### ❌ Never Do This

```javascript
// INSECURE: Don't use decode for authentication
app.get('/protected', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  const decoded = jwt.decode(token); // NO SIGNATURE VERIFICATION!
  
  if (decoded?.userId) {
    // This is INSECURE - anyone can create a fake token
    res.json({ data: 'secret data' });
  }
});
```

### ✅ Do This Instead

```javascript
// SECURE: Always verify for authentication
app.get('/protected', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  
  try {
    const decoded = await jwt.verify(token, secret); // Verifies signature
    res.json({ data: 'secret data' });
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
});
```

## Important Notes

1. **No Signature Verification**: `decode()` does not verify the token signature
2. **Sanitize Output**: When decoding untrusted tokens, sanitize the output before use
3. **Null Returns**: Returns `null` for invalid tokens instead of throwing errors
4. **Synchronous**: Unlike `sign()` and `verify()`, `decode()` is synchronous

## Common Patterns

### Safe Token Preview
```javascript
function previewToken(token, fields = ['userId', 'email', 'role']) {
  const decoded = jwt.decode(token);
  
  if (!decoded || typeof decoded === 'string') {
    return null;
  }
  
  // Only return specified fields
  const preview = {};
  fields.forEach(field => {
    if (field in decoded) {
      preview[field] = decoded[field];
    }
  });
  
  return preview;
}
```

### Token Format Validation
```javascript
function isValidTokenFormat(token) {
  if (typeof token !== 'string') {
    return false;
  }
  
  const parts = token.split('.');
  if (parts.length !== 3) {
    return false;
  }
  
  const decoded = jwt.decode(token, { complete: true });
  return decoded !== null;
}
```

## See Also

- [jwt.verify()](API-Reference-verify) - Securely verify and decode tokens
- [jwt.sign()](API-Reference-sign) - Create tokens
- [Security Best Practices](Security-&-Algorithms#best-practices) - When to use decode vs verify