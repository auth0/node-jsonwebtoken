var jwt = require('../index');

var expect = require('chai').expect;

describe('signing a token asynchronously', function() {

  describe('when signing a token', function() {
    var secret = 'shhhhhh';
    var syncToken = jwt.sign({ foo: 'bar' }, secret, { algorithm: 'HS256' });

    it('should return the same result as singing synchronously', function(done) {
      jwt.sign({ foo: 'bar' }, secret, { algorithm: 'HS256' }, function (asyncToken) {
        expect(asyncToken).to.be.a('string');
        expect(asyncToken.split('.')).to.have.length(3);
        expect(asyncToken).to.equal(syncToken);
        done();
      });
    });
  });
});
