# Migration Guide: v9.x to v10.0.0

## Breaking Changes

Version 10.0.0 introduces modern async/await patterns while maintaining backward compatibility with synchronous usage and adding callback support.

### Key Changes

1. **Default behavior is now async** - `sign()` and `verify()` return Promises by default
2. **Synchronous versions available** - New `signSync()` and `verifySync()` functions for synchronous usage
3. **Callbacks still supported** - Both `sign()` and `verify()` accept optional callbacks for backward compatibility
4. **GetPublicKeyOrSecret remains async-only** - Only works with async `verify()`, not `verifySync()`

### API Changes

#### sign() Function

**Before (v9.x):**
```javascript
// Callback style
jwt.sign(payload, secret, options, (err, token) => {
  if (err) throw err;
  console.log(token);
});

// Synchronous style (no callback)
const token = jwt.sign(payload, secret, options);
```

**After (v10.0.0):**
```javascript
// NEW: Async/await style (default)
const token = await jwt.sign(payload, secret, options);

// NEW: Promise style
jwt.sign(payload, secret, options)
  .then(token => console.log(token))
  .catch(err => console.error(err));

// BACKWARD COMPATIBLE: Callback style still works
jwt.sign(payload, secret, options, (err, token) => {
  if (err) throw err;
  console.log(token);
});

// NEW: Explicit synchronous function
const token = jwt.signSync(payload, secret, options);
```

#### verify() Function

**Before (v9.x):**
```javascript
// Callback style
jwt.verify(token, secret, options, (err, decoded) => {
  if (err) throw err;
  console.log(decoded);
});

// Synchronous style (no callback)
const decoded = jwt.verify(token, secret, options);
```

**After (v10.0.0):**
```javascript
// NEW: Async/await style (default)
const decoded = await jwt.verify(token, secret, options);

// NEW: Promise style
jwt.verify(token, secret, options)
  .then(decoded => console.log(decoded))
  .catch(err => {
    if (err.name === 'TokenExpiredError') {
      console.log('Token expired at:', err.expiredAt);
    }
  });

// BACKWARD COMPATIBLE: Callback style still works
jwt.verify(token, secret, options, (err, decoded) => {
  if (err) throw err;
  console.log(decoded);
});

// NEW: Explicit synchronous function
const decoded = jwt.verifySync(token, secret, options);
```

#### Dynamic Key Resolution (GetPublicKeyOrSecret)

**Before (v9.x):**
```javascript
const getKey = (header, callback) => {
  // Fetch key based on kid
  fetchKeyFromDatabase(header.kid, (err, key) => {
    if (err) return callback(err);
    callback(null, key);
  });
};

jwt.verify(token, getKey, options, (err, decoded) => {
  // Handle result
});
```

**After (v10.0.0):**
```javascript
// Async function (required)
const getKey = async (header) => {
  // Fetch key based on kid
  const key = await fetchKeyFromDatabase(header.kid);
  return key;
};

// Only works with async verify
const decoded = await jwt.verify(token, getKey, options);

// Note: verifySync does NOT support dynamic key resolution
// jwt.verifySync(token, getKey, options); // ❌ Will throw error!
```

### decode() Function - No Changes

The `decode()` function remains synchronous and unchanged:

```javascript
const decoded = jwt.decode(token, options);
```

### Error Handling

Error handling depends on which API style you use:

**Async/Promise style:**
```javascript
// Using try/catch
try {
  const decoded = await jwt.verify(token, secret);
} catch (err) {
  if (err.name === 'TokenExpiredError') {
    // Handle expired token
  } else if (err.name === 'JsonWebTokenError') {
    // Handle JWT error
  }
}

// Using Promise catch
jwt.verify(token, secret)
  .then(decoded => { /* success */ })
  .catch(err => {
    if (err.name === 'TokenExpiredError') {
      // Handle expired token
    }
  });
```

**Callback style (backward compatible):**
```javascript
jwt.verify(token, secret, (err, decoded) => {
  if (err) {
    if (err.name === 'TokenExpiredError') {
      // Handle expired token
    } else if (err.name === 'JsonWebTokenError') {
      // Handle JWT error
    }
  }
});
```

**Synchronous style:**
```javascript
try {
  const decoded = jwt.verifySync(token, secret);
} catch (err) {
  if (err.name === 'TokenExpiredError') {
    // Handle expired token
  } else if (err.name === 'JsonWebTokenError') {
    // Handle JWT error
  }
}
```

## Migration Strategy

### Option 1: Minimal Changes (Use Synchronous API)
If your v9.x code uses the synchronous style (no callbacks), simply replace:
- `jwt.sign()` → `jwt.signSync()`
- `jwt.verify()` → `jwt.verifySync()`

```javascript
// v9.x
const token = jwt.sign(payload, secret);
const decoded = jwt.verify(token, secret);

// v10.x - Minimal change
const token = jwt.signSync(payload, secret);
const decoded = jwt.verifySync(token, secret);
```

### Option 2: Keep Callbacks (Backward Compatible)
If your v9.x code uses callbacks, it will continue to work without changes:

```javascript
// This code works in both v9.x and v10.x
jwt.sign(payload, secret, (err, token) => {
  if (err) throw err;
  console.log(token);
});
```

### Option 3: Modernize to Async/Await (Recommended)
For the best performance and modern code style, migrate to async/await:

```javascript
// v9.x synchronous
const token = jwt.sign(payload, secret);

// v10.x async/await
const token = await jwt.sign(payload, secret);
```

### Testing Updates

If you're using this library in tests, update your test code:

**Before (v9.x):**
```javascript
it('should verify token', (done) => {
  jwt.verify(token, secret, (err, decoded) => {
    expect(err).toBeNull();
    expect(decoded.foo).toBe('bar');
    done();
  });
});
```

**After (v10.0.0):**
```javascript
it('should verify token', async () => {
  const decoded = await jwt.verify(token, secret);
  expect(decoded.foo).toBe('bar');
});
```

### TypeScript Changes

New types have been added:
- `SignCallback` - Type for sign callback function
- `VerifyCallback` - Type for verify callback function  
- `VerifyCallbackComplete` - Type for verify callback with complete option

The function signatures now support overloads for all three patterns (Promise, callback, and sync).

The `GetPublicKeyOrSecret` type has been updated:

**Before:**
```typescript
type GetPublicKeyOrSecret = (
  header: JwtHeader,
  callback: (err: any, secret?: Secret | PublicKey) => void
) => void;
```

**After:**
```typescript
type GetPublicKeyOrSecret = (
  header: JwtHeader
) => Promise<Secret | PublicKey>;
```

### Migration Steps

1. **Update all `sign()` calls** to use async/await or Promises
2. **Update all `verify()` calls** to use async/await or Promises
3. **Update error handling** from callbacks to try/catch blocks
4. **Update GetPublicKeyOrSecret functions** to return Promises
5. **Update tests** to use async/await patterns
6. **Remove any TypeScript references** to removed callback types

### New Features in v10

#### Header Validation (Security Enhancement)

Version 10.0.0 introduces automatic header validation to protect against injection attacks:

```javascript
// Header validation is enabled by default
const decoded = await jwt.verify(token, secret);

// Customize validation rules
const decoded = await jwt.verify(token, secret, {
  maxHeaderSize: 4096,        // Maximum header size (default: 8192 bytes)
  maxKidLength: 256,          // Maximum kid length (default: 1024)
  kidCharacterWhitelist: /^[a-zA-Z0-9\-]+$/  // Allowed kid characters
});

// Disable validation (not recommended)
const decoded = await jwt.verify(token, secret, {
  disableHeaderValidation: true
});
```

**Important for GetPublicKeyOrSecret users**: Headers passed to your callback are now automatically sanitized to prevent injection attacks. Only standard JWT header fields are included.

### Benefits of v10

- **Cleaner code** - No callback hell, better error handling
- **Modern JavaScript** - Uses latest language features
- **Better TypeScript support** - Simpler types, better inference
- **Easier testing** - Async/await tests are more readable
- **Better performance** - No callback overhead, cleaner stack traces
- **Enhanced security** - Automatic header validation prevents injection attacks

### Need Help?

If you encounter issues during migration, please check our [GitHub issues](https://github.com/auth0/node-jsonwebtoken/issues) or create a new issue with details about your migration challenges.