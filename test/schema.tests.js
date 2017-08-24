var jwt = require('../index');
var expect = require('chai').expect;
var fs = require('fs');

describe('schema', function() {

  describe('sign options', function() {

    var cert_rsa_priv = fs.readFileSync(__dirname + '/rsa-private.pem');
    var cert_ecdsa_priv = fs.readFileSync(__dirname + '/ecdsa-private.pem');

    function sign(options) {
      var isEcdsa = options.algorithm && options.algorithm.indexOf('ES') === 0;
      jwt.sign({foo: 123}, isEcdsa ? cert_ecdsa_priv : cert_rsa_priv, options);
    }

    it('should validate expiresIn', function () {
      expect(function () {
        sign({ expiresIn: '1 monkey' });
      }).to.throw(/"expiresIn" should be a number of seconds or string representing a timespan/);
      expect(function () {
        sign({ expiresIn: 1.1 });
      }).to.throw(/"expiresIn" should be a number of seconds or string representing a timespan/);
      sign({ expiresIn: '10s' });
      sign({ expiresIn: 10 });
    });

    it('should validate notBefore', function () {
      expect(function () {
        sign({ notBefore: '1 monkey' });
      }).to.throw(/"notBefore" should be a number of seconds or string representing a timespan/);
      expect(function () {
        sign({ notBefore: 1.1 });
      }).to.throw(/"notBefore" should be a number of seconds or string representing a timespan/);
      sign({ notBefore: '10s' });
      sign({ notBefore: 10 });
    });

    it('should validate audience', function () {
      expect(function () {
        sign({ audience: 10 });
      }).to.throw(/"audience" must be a string or array/);
      sign({ audience: 'urn:foo' });
      sign({ audience: ['urn:foo'] });
    });

    it('should validate algorithm', function () {
      expect(function () {
        sign({ algorithm: 'foo' });
      }).to.throw(/"algorithm" must be a valid string enum value/);
      sign({algorithm: 'RS256'});
      sign({algorithm: 'RS384'});
      sign({algorithm: 'RS512'});
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

    it('should validate issuer', function () {
      expect(function () {
        sign({ issuer: 10 });
      }).to.throw(/"issuer" must be a string/);
      sign({issuer: 'foo'});
    });

    it('should validate subject', function () {
      expect(function () {
        sign({ subject: 10 });
      }).to.throw(/"subject" must be a string/);
      sign({subject: 'foo'});
    });

    it('should validate noTimestamp', function () {
      expect(function () {
        sign({ noTimestamp: 10 });
      }).to.throw(/"noTimestamp" must be a boolean/);
      sign({noTimestamp: true});
    });

    it('should validate keyid', function () {
      expect(function () {
        sign({ keyid: 10 });
      }).to.throw(/"keyid" must be a string/);
      sign({keyid: 'foo'});
    });

  });

  describe('sign payload registered claims', function() {

    function sign(payload) {
      jwt.sign(payload, 'foo123');
    }

    it('should validate iat', function () {
      expect(function () {
        sign({ iat: '1 monkey' });
      }).to.throw(/"iat" should be a number of seconds/);
      sign({ iat: 10.1 });
    });

    it('should validate exp', function () {
      expect(function () {
        sign({ exp: '1 monkey' });
      }).to.throw(/"exp" should be a number of seconds/);
      sign({ exp: 10.1 });
    });

    it('should validate nbf', function () {
      expect(function () {
        sign({ nbf: '1 monkey' });
      }).to.throw(/"nbf" should be a number of seconds/);
      sign({ nbf: 10.1 });
    });

  });

});