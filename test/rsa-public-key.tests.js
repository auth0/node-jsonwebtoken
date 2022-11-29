const jwt = require('../');
const PS_SUPPORTED = require('../lib/psSupported');
const expect = require('chai').expect;
const {generateKeyPairSync} = require('crypto')

describe('public key start with BEGIN RSA PUBLIC KEY', function () {

  it('should work for RS family of algorithms', function (done) {
    var fs = require('fs');
    var cert_pub = fs.readFileSync(__dirname + '/rsa-public-key.pem');
    var cert_priv = fs.readFileSync(__dirname + '/rsa-private.pem');

    var token = jwt.sign({ foo: 'bar' }, cert_priv, { algorithm: 'RS256'});

    jwt.verify(token, cert_pub, done);
  });

  it('should not work for RS algorithms when modulus length is less than 2048 when allowInsecureKeySizes is false or not set', function (done) {
    const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 1024 });

    expect(function() {
      jwt.sign({ foo: 'bar' }, privateKey, { algorithm: 'RS256'})
    }).to.throw(Error, 'minimum key size');

    done()
  });

  it('should work for RS algorithms when modulus length is less than 2048 when allowInsecureKeySizes is true', function (done) {
    const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 1024 });

    jwt.sign({ foo: 'bar' }, privateKey, { algorithm: 'RS256', allowInsecureKeySizes: true}, done)
  });

  if (PS_SUPPORTED) {
    it('should work for PS family of algorithms', function (done) {
      var fs = require('fs');
      var cert_pub = fs.readFileSync(__dirname + '/rsa-public-key.pem');
      var cert_priv = fs.readFileSync(__dirname + '/rsa-private.pem');

      var token = jwt.sign({ foo: 'bar' }, cert_priv, { algorithm: 'PS256'});

      jwt.verify(token, cert_pub, done);
    });
  }

});
