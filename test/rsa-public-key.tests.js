const jwt = require('../');
const PS_SUPPORTED = require('../lib/psSupported');

describe('public key start with BEGIN RSA PUBLIC KEY', function () {

  it('should work for RS family of algorithms', function (done) {
    const fs = require('fs');
    const cert_pub = fs.readFileSync(__dirname + '/rsa-public-key.pem');
    const cert_priv = fs.readFileSync(__dirname + '/rsa-private.pem');

    const token = jwt.sign({ foo: 'bar' }, cert_priv, { algorithm: 'RS256'});

    jwt.verify(token, cert_pub, done);
  });

  if (PS_SUPPORTED) {
    it('should work for PS family of algorithms', function (done) {
      const fs = require('fs');
      const cert_pub = fs.readFileSync(__dirname + '/rsa-public-key.pem');
      const cert_priv = fs.readFileSync(__dirname + '/rsa-private.pem');

      const token = jwt.sign({ foo: 'bar' }, cert_priv, { algorithm: 'PS256'});

      jwt.verify(token, cert_pub, done);
    });
  }

});
