var jwt = require('../index');

var assert = require('chai').assert;

describe('node-jsonwebtoken interface', function () {
  describe('verify', function () {
    describe('without callback', function () {
      it('returns sync', function () {
        var token = jwt.sign({ foo: 'bar' }, 'secret'),
            decoded = jwt.verify(token, 'secret');

        assert.ok(decoded.foo);
        assert.equal(decoded.foo, 'bar');
      });

      it('throws exceptions sync', function () {
        assert.throw(function () { jwt.verify(null, 'secret'); });
      });
    });

    describe('with callback', function () {
      it('returns async', function (done) {
        var token = jwt.sign({ foo: 'bar' }, 'secret');

        jwt.verify(token, 'secret', function (err, decoded) {
          assert.ok(decoded.foo);
          assert.ok(decoded.foo, 'bar');
          done();
        });
      });

      it('throws exceptions to callback', function (done) {
        jwt.verify(null, 'secret', function (err, decoded) {
          assert.isUndefined(decoded);
          assert.isNotNull(err);
          done();
        });
      });
    });
  });
});