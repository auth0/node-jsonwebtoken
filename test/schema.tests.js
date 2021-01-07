var jwt = require('../index');
var expect = require('chai').expect;
var fs = require('fs');
var PS_SUPPORTED = require('../lib/psSupported');

describe('schema', function() {

  describe('sign options', function() {

    var cert_rsa_priv = fs.readFileSync(__dirname + '/rsa-private.pem');
    var cert_ecdsa_priv = fs.readFileSync(__dirname + '/ecdsa-private.pem');

    function sign(options) {
      var isEcdsa = options.algorithm && options.algorithm.indexOf('ES') === 0;
      jwt.sign({foo: 123}, isEcdsa ? cert_ecdsa_priv : cert_rsa_priv, options);
    }

    it('should validate algorithm', function () {
      expect(function () {
        sign({ algorithm: 'foo' });
      }).to.throw(/"algorithm" must be a valid string enum value/);
      sign({algorithm: 'RS256'});
      sign({algorithm: 'RS384'});
      sign({algorithm: 'RS512'});
      if (PS_SUPPORTED) {
        sign({algorithm: 'PS256'});
        sign({algorithm: 'PS384'});
        sign({algorithm: 'PS512'});
      }
      sign({algorithm: 'ES256'});
      sign({algorithm: 'ES384'});
      sign({algorithm: 'ES512'});
      sign({algorithm: 'HS256'});
      sign({algorithm: 'HS384'});
      sign({algorithm: 'HS512'});
      sign({algorithm: 'none'});
    });

    it('should validate header', function () {
      expect(function () {
        sign({ header: 'foo' });
      }).to.throw(/"header" must be an object/);
      sign({header: {}});
    });

    it('should validate encoding', function () {
      expect(function () {
        sign({ encoding: 10 });
      }).to.throw(/"encoding" must be a string/);
      sign({encoding: 'utf8'});
    });

    it('should validate noTimestamp', function () {
      expect(function () {
        sign({ noTimestamp: 10 });
      }).to.throw(/"noTimestamp" must be a boolean/);
      sign({noTimestamp: true});
    });
  });

  describe('sign payload registered claims', function() {

    function sign(payload) {
      jwt.sign(payload, 'foo123');
    }

    it('should validate exp', function () {
      expect(function () {
        sign({ exp: '1 monkey' });
      }).to.throw(/"exp" should be a number of seconds/);
      sign({ exp: 10.1 });
    });

  });

});