var jwt = require('../index');
var expect = require('chai').expect;
var jws = require('jws');

describe('signing a token', function() {

  describe('when signing a token', function() {
    var secret = 'shhhhhh';

    it('should return a token in the correct format', function() {
      var syncToken = jwt.sign({ foo: 'bar' }, secret, { algorithm: 'HS256' });
      expect(syncToken).to.be.a('string');
      expect(syncToken.split('.')).to.have.length(3);
    });

    it('should work', function () {
      jwt.sign({abc: 1}, "secret", {});
    });

    it('should return error when secret is not a cert for RS256', function() {
      //this throw an error because the secret is not a cert and RS256 requires a cert.
      var sign = jwt.sign.bind(null, { foo: 'bar' }, secret, { algorithm: 'RS256' });
      expect(sign).to.throw(Error);
    });

    it('should return error on wrong arguments', function() {
      //this throw an error because the secret is not a cert and RS256 requires a cert.
      var sign = jwt.sign.bind(null, { foo: 'bar' }, secret, { notBefore: {} });
      expect(sign).to.throw(Error);
    });

    it('should return error on wrong arguments (2)', function() {
      var sign = jwt.sign.bind(null, 'string', 'secret', { noTimestamp: true });
      expect(sign).to.throw('invalid noTimestamp option for string payload');
    });

    it('should not stringify the payload', function () {
      var token = jwt.sign('string', 'secret', {});
      expect(jws.decode(token).payload).to.equal('string');
    });
  });
});
