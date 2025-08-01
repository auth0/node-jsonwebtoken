const jwt = require('../index');
const fs = require('fs');
const PS_SUPPORTED = require('../lib/psSupported');

describe('schema', () => {

  describe('sign options', () => {
    const cert_rsa_priv = fs.readFileSync(`${__dirname  }/rsa-private.pem`);
    const cert_ecdsa_priv = fs.readFileSync(`${__dirname  }/ecdsa-private.pem`);
    const cert_secp384r1_priv = fs.readFileSync(`${__dirname  }/secp384r1-private.pem`);
    const cert_secp521r1_priv = fs.readFileSync(`${__dirname  }/secp521r1-private.pem`);

    function sign(options, secretOrPrivateKey) {
      jwt.sign({foo: 123}, secretOrPrivateKey, options);
    }

    it('should validate algorithm', () => {
      expect(() => {
        sign({ algorithm: 'foo' }, cert_rsa_priv);
      }).toThrow(/"algorithm" must be a valid string enum value/);
      sign({algorithm: 'RS256'}, cert_rsa_priv);
      sign({algorithm: 'RS384'}, cert_rsa_priv);
      sign({algorithm: 'RS512'}, cert_rsa_priv);
      if (PS_SUPPORTED) {
        sign({algorithm: 'PS256'}, cert_rsa_priv);
        sign({algorithm: 'PS384'}, cert_rsa_priv);
        sign({algorithm: 'PS512'}, cert_rsa_priv);
      }
      sign({algorithm: 'ES256'}, cert_ecdsa_priv);
      sign({algorithm: 'ES384'}, cert_secp384r1_priv);
      sign({algorithm: 'ES512'}, cert_secp521r1_priv);
      // ES256K - secp256k1 curve
      const cert_secp256k1_priv = fs.readFileSync(`${__dirname}/secp256k1-private.pem`);
      sign({algorithm: 'ES256K'}, cert_secp256k1_priv);
      // EdDSA
      const cert_ed25519_priv = fs.readFileSync(`${__dirname}/ed25519-private.pem`);
      sign({algorithm: 'EdDSA'}, cert_ed25519_priv);
      sign({algorithm: 'HS256'}, 'superSecret');
      sign({algorithm: 'HS384'}, 'superSecret');
      sign({algorithm: 'HS512'}, 'superSecret');
    });

    it('should validate header', () => {
      expect(() => {
        sign({ header: 'foo' }, 'superSecret');
      }).toThrow(/"header" must be an object/);
      sign({header: {}}, 'superSecret');
    });

    it('should validate encoding', () => {
      expect(() => {
        sign({ encoding: 10 }, 'superSecret');
      }).toThrow(/"encoding" must be a string/);
      sign({encoding: 'utf8'},'superSecret');
    });

    it('should validate noTimestamp', () => {
      expect(() => {
        sign({ noTimestamp: 10 }, 'superSecret');
      }).toThrow(/"noTimestamp" must be a boolean/);
      sign({noTimestamp: true}, 'superSecret');
    });
  });

  describe('sign payload registered claims', () => {

    function sign(payload) {
      jwt.sign(payload, 'foo123');
    }

    it('should validate exp', () => {
      expect(() => {
        sign({ exp: '1 monkey' });
      }).toThrow(/"exp" should be a number of seconds/);
      sign({ exp: 10.1 });
    });

  });

});
