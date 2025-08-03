# Security & Algorithms

This page covers security considerations and supported algorithms for the `jsonwebtoken` library.

## Table of Contents
- [Supported Algorithms](#supported-algorithms)
- [Prototype Pollution Protection](#prototype-pollution-protection)
- [Denial of Service (DoS) Protection](#denial-of-service-dos-protection)
- [Best Practices](#best-practices)
- [Security Warnings](#security-warnings)

## Supported Algorithms

The library supports the following algorithms:

### HMAC Algorithms
- **HS256** - HMAC using SHA-256
- **HS384** - HMAC using SHA-384
- **HS512** - HMAC using SHA-512

### RSA Algorithms
- **RS256** - RSASSA-PKCS1-v1_5 using SHA-256
- **RS384** - RSASSA-PKCS1-v1_5 using SHA-384
- **RS512** - RSASSA-PKCS1-v1_5 using SHA-512
- **PS256** - RSASSA-PSS using SHA-256 and MGF1 with SHA-256
- **PS384** - RSASSA-PSS using SHA-384 and MGF1 with SHA-384
- **PS512** - RSASSA-PSS using SHA-512 and MGF1 with SHA-512

### ECDSA Algorithms
- **ES256** - ECDSA using P-256 and SHA-256
- **ES384** - ECDSA using P-384 and SHA-384
- **ES512** - ECDSA using P-521 and SHA-512
- **ES256K** - ECDSA using secp256k1 and SHA-256

### EdDSA Algorithm
- **EdDSA** - EdDSA signature algorithms (Ed25519 and Ed448)

### None Algorithm
- **none** - No digital signature or MAC (⚠️ Use with extreme caution)

## Prototype Pollution Protection

As of v10.0.0, the library includes built-in protection against prototype pollution attacks.

### What is Prototype Pollution?

Prototype pollution is a JavaScript vulnerability where an attacker can inject properties into `Object.prototype`, affecting all objects in the application. In the context of JWTs, this could allow attackers to:

1. Add properties to all objects (e.g., `isAdmin: true`)
2. Bypass security checks
3. Escalate privileges
4. In worst cases, achieve remote code execution

### How the Library Prevents It

The library protects against prototype pollution in two key areas:

#### 1. Header Injection Protection

When signing tokens with custom headers, dangerous keys are filtered out:

```javascript
// This attack is prevented
const maliciousOptions = {
  header: {
    "__proto__": {
      "isAdmin": true
    }
  }
};

const token = await jwt.sign(payload, secret, maliciousOptions);
// The __proto__ key is filtered out, preventing pollution
```

#### 2. JSON Parsing Protection

When decoding tokens, the library uses a safe JSON parser that filters dangerous keys:

```javascript
// Even if a JWT contains __proto__ in its payload
// it won't pollute the prototype when decoded
const decoded = jwt.decode(maliciousToken);
// Dangerous keys like __proto__, constructor, and prototype are removed
```

### Protected Keys

The following keys are filtered to prevent pollution:
- `__proto__`
- `constructor`
- `prototype`

## Denial of Service (DoS) Protection

As of v10.0.0, the library includes built-in protection against DoS attacks through configurable size and complexity limits.

### Attack Vectors Prevented

#### 1. Large Token Attack
Attackers can create massive JWTs to exhaust server memory:
```javascript
// This attack is now prevented by default
const hugePayload = {
  data: 'A'.repeat(100 * 1024 * 1024) // 100MB
};
const token = await jwt.sign(hugePayload, secret);
// Throws: JWT exceeds maximum allowed size
```

#### 2. Deep Nesting Attack
Deeply nested objects cause exponential parsing time:
```javascript
// This attack is now prevented
let payload = { a: 1 };
for (let i = 0; i < 1000; i++) {
  payload = { nested: payload };
}
const token = await jwt.sign(payload, secret);
// Throws: JWT payload exceeds maximum allowed depth
```

#### 3. Claim Explosion Attack
Thousands of claims can exhaust memory:
```javascript
// This attack is now prevented
const payload = {};
for (let i = 0; i < 50000; i++) {
  payload[`claim${i}`] = `value${i}`;
}
const token = await jwt.sign(payload, secret);
// Throws: JWT payload exceeds maximum allowed claim count
```

### Configurable Limits

All limits can be configured per operation:

```javascript
// Custom limits for sign
const token = await jwt.sign(payload, secret, {
  maxTokenSize: 500 * 1024,    // 500KB total token size
  maxPayloadSize: 200 * 1024,  // 200KB payload size
  maxPayloadDepth: 100,        // 100 levels deep
  maxClaimCount: 2000          // 2000 total claims
});

// Custom limits for verify
const decoded = await jwt.verify(token, secret, {
  maxTokenSize: 500 * 1024,
  maxPayloadSize: 200 * 1024,
  maxPayloadDepth: 100,
  maxClaimCount: 2000
});

// Custom limits for decode
const payload = jwt.decode(token, {
  maxTokenSize: 500 * 1024,
  maxPayloadSize: 200 * 1024,
  maxPayloadDepth: 100,
  maxClaimCount: 2000
});
```

### Default Limits

The library uses sensible defaults that work for 99.9% of legitimate use cases:

| Limit | Default Value | Description |
|-------|---------------|-------------|
| `maxTokenSize` | 250KB | Maximum size of the entire JWT string |
| `maxPayloadSize` | 100KB | Maximum size of the decoded payload |
| `maxPayloadDepth` | 50 | Maximum nesting depth of objects |
| `maxClaimCount` | 1000 | Maximum total number of claims |

### Disabling DoS Protection

For backward compatibility or special use cases, DoS protection can be disabled:

```javascript
// ⚠️ WARNING: Only disable for trusted inputs
const token = await jwt.sign(largePayload, secret, {
  disableDoSProtection: true
});

const decoded = await jwt.verify(token, secret, {
  disableDoSProtection: true
});
```

### Best Practices for DoS Protection

1. **Keep Default Limits**: The defaults are generous for legitimate use
2. **Monitor Token Sizes**: Log warnings when tokens approach limits
3. **Validate Before Signing**: Check payload size before creating tokens
4. **Set Appropriate Limits**: Adjust based on your specific use case
5. **Never Disable for Public APIs**: Always enforce limits on untrusted input

## Best Practices

### 1. Always Verify Tokens

Never trust a JWT without verification:

```javascript
// ❌ Bad - No verification
const decoded = jwt.decode(token);

// ✅ Good - Proper verification
const decoded = await jwt.verify(token, secret);
```

### 2. Use Strong Keys

- **HMAC**: Use keys at least 256 bits (32 bytes) long
- **RSA**: Use keys with at least 2048-bit modulus
- **ECDSA**: Use appropriate curves (P-256, P-384, P-521)

```javascript
// ❌ Bad - Weak secret
const token = await jwt.sign(payload, 'secret123');

// ✅ Good - Strong secret
const token = await jwt.sign(payload, crypto.randomBytes(32));
```

### 3. Always Specify Algorithms

When verifying, always specify allowed algorithms:

```javascript
// ❌ Bad - No algorithm restriction
const decoded = await jwt.verify(token, publicKey);

// ✅ Good - Explicit algorithm
const decoded = await jwt.verify(token, publicKey, { 
  algorithms: ['RS256'] 
});
```

### 4. Set Token Expiration

Always set token expiration to limit exposure:

```javascript
const token = await jwt.sign(payload, secret, {
  expiresIn: '1h' // Token expires in 1 hour
});
```

### 5. Validate All Claims

Verify audience, issuer, and other claims:

```javascript
const decoded = await jwt.verify(token, secret, {
  audience: 'your-app.com',
  issuer: 'auth.your-app.com',
  clockTolerance: 10 // 10 seconds clock skew tolerance
});
```

## Security Warnings

### 1. The 'none' Algorithm

The `none` algorithm provides **NO security**. It must be explicitly enabled:

```javascript
// ⚠️ DANGEROUS - Only use for testing
const unsignedToken = await jwt.sign(payload, '', {
  algorithm: 'none',
  allowInsecureNoneAlgorithm: true
});
```

### 2. Algorithm Confusion

Never allow tokens to specify their own algorithm without validation:

```javascript
// ❌ Bad - Algorithm from token
const header = jwt.decode(token, { complete: true }).header;
const decoded = await jwt.verify(token, key, { 
  algorithms: [header.alg] 
});

// ✅ Good - Predefined algorithms
const decoded = await jwt.verify(token, key, { 
  algorithms: ['RS256', 'RS384'] 
});
```

### 3. Key Storage

- Never commit keys to version control
- Use environment variables or secure key management systems
- Rotate keys regularly
- Use different keys for different environments

### 4. Header Injection

Be cautious with dynamic header values:

```javascript
// ✅ Safe - Prototype pollution protection is automatic
const token = await jwt.sign(payload, secret, {
  header: userProvidedHeader // Safe due to filtering
});
```

### 5. Clock Skew

Account for clock differences between systems:

```javascript
const decoded = await jwt.verify(token, secret, {
  clockTolerance: 60 // Allow 60 seconds clock skew
});
```

## Additional Resources

- [JWT Best Current Practices (RFC 8725)](https://tools.ietf.org/html/rfc8725)
- [JSON Web Token (RFC 7519)](https://tools.ietf.org/html/rfc7519)
- [JWT.io Security Best Practices](https://jwt.io/introduction#security)