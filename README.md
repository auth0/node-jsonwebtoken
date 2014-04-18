# jsonwebtoken [![Build Status](https://secure.travis-ci.org/auth0/node-jsonwebtoken.png)](http://travis-ci.org/auth0/node-jsonwebtoken)


An implementation of [JSON Web Tokens](http://self-issued.info/docs/draft-ietf-oauth-json-web-token.html).

This was developed against `draft-ietf-oauth-json-web-token-08`. It makes use of [node-jws](https://github.com/brianloveswords/node-jws)

# Install

```bash
$ npm install jsonwebtoken
```

# Usage

### jwt.sign(payload, secretOrPrivateKey, options)

(Synchronous) Returns the JsonWebToken as string

`payload` could be an literal, buffer or string

`secretOrPrivateKey` is a string or buffer containing either the secret for HMAC algorithms, or the PEM
encoded private key for RSA and ECDSA.

`options`:

* `algorithm` (default: `HS256`)
* `expiresInMinutes`
* `audience`
* `subject`
* `issuer`

If `payload` is not a buffer or a string, it will be coerced into a string
using `JSON.stringify`.

If any `expiresInMinutes`, `audience`, `subject`, `issuer` are not provided, there is no default. The  jwt generated won't include those properties in the payload.

Example

```js
// sign with default (HMAC SHA256)
var jwt = require('jsonwebtoken');
var token = jwt.sign({ foo: 'bar' }, 'shhhhh');

// sign with RSA SHA256
var cert = fs.readFileSync('private.key');  // get private key
var token = jwt.sign({ foo: 'bar' }, cert, { algorithm: 'RS256'});
```

### jwt.verify(token, secretOrPublicKey, options, callback)

(Synchronous with callback) Returns the payload decoded if the signature (and optionally expiration, audience, issuer) are valid. If not, it will return the error.

`token` is the JsonWebToken string

`secretOrPublicKey` is a string or buffer containing either the secret for HMAC algorithms, or the PEM
encoded public key for RSA and ECDSA.

`options`

* `audience`: if you want to check audience (`aud`), provide a value here
* `issuer`: if you want to check issuer (`iss`), provide a value here

```js
// verify a token symmetric
jwt.verify(token, 'shhhhh', function(err, decoded) {
  console.log(decoded.foo) // bar
});

// invalid token
jwt.verify(token, 'wrong-secret', function(err, decoded) {
  // err 
  // decoded undefined
});

// verify a token asymmetric
var cert = fs.readFileSync('public.pem');  // get public key
jwt.verify(token, cert, function(err, decoded) {
  console.log(decoded.foo) // bar
});

// verify audience
var cert = fs.readFileSync('public.pem');  // get public key
jwt.verify(token, cert, { audience: 'urn:foo' }, function(err, decoded) {
  // if audience mismatch, err == invalid audience
});

// verify issuer
var cert = fs.readFileSync('public.pem');  // get public key
jwt.verify(token, cert, { audience: 'urn:foo', issuer: 'urn:issuer' }, function(err, decoded) {
  // if issuer mismatch, err == invalid issuer
});
      
```

## Algorithms supported

Array of supported algorithms. The following algorithms are currently supported.

alg Parameter Value | Digital Signature or MAC Algorithm 
----------------|----------------------------
HS256 | HMAC using SHA-256 hash algorithm 
HS384 | HMAC using SHA-384 hash algorithm 
HS512 | HMAC using SHA-512 hash algorithm 
RS256 | RSASSA using SHA-256 hash algorithm
RS384 | RSASSA using SHA-384 hash algorithm
RS512 | RSASSA using SHA-512 hash algorithm
ES256 | ECDSA using P-256 curve and SHA-256 hash algorithm
ES384 | ECDSA using P-384 curve and SHA-384 hash algorithm
ES512 | ECDSA using P-521 curve and SHA-512 hash algorithm
none | No digital signature or MAC value included



# TODO

* X.509 certificate chain is not checked

# License

MIT

