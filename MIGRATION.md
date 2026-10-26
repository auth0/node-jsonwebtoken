# Migration notes (fork)

## `verify()` rejects unknown options (HU-03)

`jwt.verify()` used to ignore any option it did not read. A typo such as
`algoritms` silently dropped the algorithm allow-list. It now accepts only
the documented options:

`algorithms`, `audience`, `issuer`, `subject`, `jwtid`, `complete`,
`ignoreExpiration`, `ignoreNotBefore`, `clockTolerance`, `maxAge`, `nonce`,
`clockTimestamp`, `allowInvalidAsymmetricKeyTypes`.

Any other name throws (or is passed to the callback as) a
`JsonWebTokenError` with the message `"<name>" is not an allowed option`.

### What to change

| You pass to `verify()` | Change it to |
|---|---|
| `algorithm: 'HS256'` | `algorithms: ['HS256']`; `algorithm` never restricted the allow-list |
| `jetid` (or another misspelled name) | the correct name, e.g. `jwtid` |
| `typ`, `exp`, `nbf` | remove them; `verify()` reads these from the token, not from the options |
| `sign()` options such as `expiresIn`, `notBefore`, `noTimestamp` | remove them, or use `maxAge` / `clockTolerance` |

If you share one options object between `sign()` and `verify()`, build
separate objects for each call.
