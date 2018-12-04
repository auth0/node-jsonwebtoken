var jwt = require('../index');
var sjcl = require('sjcl');
var assert = require('chai').assert;
var expect = require('chai').expect;
var cryptoManager = {};
cryptoManager.keys = {};
cryptoManager.sign = function (keyname, hash) {

  if(!cryptoManager.keys[keyname]) {
    cryptoManager.keys[keyname] = sjcl.ecc.ecdsa.generateKeys(sjcl.ecc.curves.k256)
  }
  var pair = cryptoManager.keys[keyname];
  var sig = pair.sec.sign(sjcl.codec.hex.toBits(hash));
  return sjcl.codec.hex.fromBits(sig);
}
cryptoManager.verify = function (keyname, hash, signature) {

  if(!cryptoManager.keys[keyname]) {
    throw new Error('Key not found');
  }
  var pair = cryptoManager.keys[keyname];
  return pair.pub.verify(sjcl.codec.hex.toBits(hash), sjcl.codec.hex.toBits(signature));
}
describe('CryptoManager Test', () => {

  it('should not accept s crypto manager that not implements sign', function () {
    function badFn() {
      var payload = {iat: Math.floor(Date.now() / 1000)};

      jwt.sign(payload, null, {cryptoManager: {}, keyName: 'test', algorithm: 'ES256k'});
    }
    expect(badFn).to.throw(Error, '"cryptoManager" must be an object that implements sign');
  });

  it('should Sign using the cripto manager', function () {
    var payload = { iat: Math.floor(Date.now() / 1000 ) };

    var signed = jwt.sign(payload, null, {cryptoManager: cryptoManager, keyName: 'test', algorithm: 'ES256k'});
    assert.isDefined(signed);

  });

  it('should Sign using the cripto manager and return using callback', function (done) {
    var payload = { iat: Math.floor(Date.now() / 1000 ) };

    jwt.sign(payload, null, {cryptoManager: cryptoManager, keyName: 'test', algorithm: 'ES256k'}, function (err, signed) {
      assert.isDefined(signed);
      done();
    });

  });

  it('should not accept ES256k without crypto manager', function () {
    function badFn() {
      var payload = {iat: Math.floor(Date.now() / 1000)};

      jwt.sign(payload, null, { algorithm: 'ES256k'});
    }
    expect(badFn).to.throw(Error, 'ES256k is only supported with cryptoManager');
  });

  it('should not accept keyName without crypto manager', function () {
    function badFn() {
      var payload = {iat: Math.floor(Date.now() / 1000)};

      jwt.sign(payload, null, {keyName: 'test', algorithm: 'ES256'});
    }
    expect(badFn).to.throw(Error, 'Keyname is only supported with cryptoManager');
  });

  it('should not accept crypto manager without keyname', function () {
    function badFn() {
      var payload = {iat: Math.floor(Date.now() / 1000)};

      jwt.sign(payload, null, {cryptoManager: cryptoManager, algorithm: 'ES256k'});
    }
    expect(badFn).to.throw(Error, 'Keyname is required when using a cryptoManager');
  });

  it('should propagate errors throw by the crypto manager', function () {
    function badFn() {
      var payload = {iat: Math.floor(Date.now() / 1000)};

      jwt.sign(payload, null, {keyName: 'test', cryptoManager: {sign: function () { throw new Error('Refuse to sign')}}, algorithm: 'ES256k'});
    }
    expect(badFn).to.throw(Error, 'Refuse to sign');
  });

  it('should propagate errors throw by the crypto manager using callback', function (done) {

    var payload = {iat: Math.floor(Date.now() / 1000)};

    jwt.sign(payload, null, {keyName: 'test', cryptoManager: {sign: function () { throw new Error('Refuse to sign')}}, algorithm: 'ES256k'},
      function(err, result){
        assert.isDefined(err);
        assert.isUndefined(result);
        done();
      });
  });

  it('should verify', function () {
    var payload = { iat: Math.floor(Date.now() / 1000 ) };
    var signed = jwt.sign(payload, null, {cryptoManager: cryptoManager, keyName: 'test', algorithm: 'ES256k'});
    assert.isDefined(signed);
    var payload =  jwt.verify(signed, null, {cryptoManager: cryptoManager, keyName: 'test'});
    assert.isDefined(payload);
  });

  it('should verify with callback', function (done) {
    var payload = { iat: Math.floor(Date.now() / 1000 ) };
    var signed = jwt.sign(payload, null, {cryptoManager: cryptoManager, keyName: 'test', algorithm: 'ES256k'});
    assert.isDefined(signed);
    jwt.verify(signed, null, {cryptoManager: cryptoManager, keyName: 'test'}, function (err, payload) {
      assert.isDefined(payload);
      done();
    });

  });

});
