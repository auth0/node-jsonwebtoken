const jwt = require('../');
const PS_SUPPORTED = require('../lib/psSupported');
const {generateKeyPairSync} = require('crypto')

describe('public key start with BEGIN RSA PUBLIC KEY', () => {

  it('should work for RS family of algorithms', (done) => {
    const fs = require('fs');
    const cert_pub = fs.readFileSync(`${__dirname  }/rsa-public-key.pem`);
    const cert_priv = fs.readFileSync(`${__dirname  }/rsa-private.pem`);

    const token = jwt.sign({ foo: 'bar' }, cert_priv, { algorithm: 'RS256'});

    jwt.verify(token, cert_pub, done);
  });

  it('should not work for RS algorithms when modulus length is less than 2048 when allowInsecureKeySizes is false or not set', (done) => {
    const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 1024 });

    expect(() => {
      jwt.sign({ foo: 'bar' }, privateKey, { algorithm: 'RS256'})
    }).to.throw(Error, 'minimum key size');

    done()
  });

  it('should work for RS algorithms when modulus length is less than 2048 when allowInsecureKeySizes is true', (done) => {
    const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 1024 });

    jwt.sign({ foo: 'bar' }, privateKey, { algorithm: 'RS256', allowInsecureKeySizes: true}, done)
  });

  if (PS_SUPPORTED) {
    it('should work for PS family of algorithms', (done) => {
      const fs = require('fs');
      const cert_pub = fs.readFileSync(`${__dirname  }/rsa-public-key.pem`);
      const cert_priv = fs.readFileSync(`${__dirname  }/rsa-private.pem`);

      const token = jwt.sign({ foo: 'bar' }, cert_priv, { algorithm: 'PS256'});

      jwt.verify(token, cert_pub, done);
    });
  }

});
