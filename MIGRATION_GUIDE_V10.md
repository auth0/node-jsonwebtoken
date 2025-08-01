# Migration Guide: v9.x to v10.0.0

## Breaking Changes

Version 10.0.0 introduces a complete migration from callback-based APIs to modern async/await patterns. This is a major breaking change that requires updating all code using this library.

### Key Changes

1. **All callbacks removed** - `sign()` and `verify()` no longer accept callbacks
2. **All functions return Promises** - Must use `await` or `.then()`
3. **GetPublicKeyOrSecret is now async** - Must return a Promise
4. **Error handling via try/catch** - No more error-first callbacks

### API Changes

#### sign() Function

**Before (v9.x):**
```javascript
// Callback style
jwt.sign(payload, secret, options, (err, token) => {
  if (err) throw err;
  console.log(token);
});

// Synchronous style
const token = jwt.sign(payload, secret, options);
```

**After (v10.0.0):**
```javascript
// Async/await style
try {
  const token = await jwt.sign(payload, secret, options);
  console.log(token);
} catch (err) {
  throw err;
}

// Promise style
jwt.sign(payload, secret, options)
  .then(token => console.log(token))
  .catch(err => console.error(err));
```

#### verify() Function

**Before (v9.x):**
```javascript
// Callback style
jwt.verify(token, secret, options, (err, decoded) => {
  if (err) throw err;
  console.log(decoded);
});

// Synchronous style
const decoded = jwt.verify(token, secret, options);
```

**After (v10.0.0):**
```javascript
// Async/await style
try {
  const decoded = await jwt.verify(token, secret, options);
  console.log(decoded);
} catch (err) {
  if (err.name === 'TokenExpiredError') {
    console.log('Token expired at:', err.expiredAt);
  }
  throw err;
}
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
const getKey = async (header) => {
  // Fetch key based on kid
  const key = await fetchKeyFromDatabase(header.kid);
  return key;
};

try {
  const decoded = await jwt.verify(token, getKey, options);
  // Handle result
} catch (err) {
  // Handle error
}
```

### decode() Function - No Changes

The `decode()` function remains synchronous and unchanged:

```javascript
const decoded = jwt.decode(token, options);
```

### Error Handling

All errors are now thrown instead of being passed to callbacks:

**Before (v9.x):**
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

**After (v10.0.0):**
```javascript
try {
  const decoded = await jwt.verify(token, secret);
} catch (err) {
  if (err.name === 'TokenExpiredError') {
    // Handle expired token
  } else if (err.name === 'JsonWebTokenError') {
    // Handle JWT error
  }
}
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

The following types have been removed:
- `SignCallback`
- `VerifyCallback`

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

### Benefits of v10

- **Cleaner code** - No callback hell, better error handling
- **Modern JavaScript** - Uses latest language features
- **Better TypeScript support** - Simpler types, better inference
- **Easier testing** - Async/await tests are more readable
- **Better performance** - No callback overhead, cleaner stack traces

### Need Help?

If you encounter issues during migration, please check our [GitHub issues](https://github.com/auth0/node-jsonwebtoken/issues) or create a new issue with details about your migration challenges.