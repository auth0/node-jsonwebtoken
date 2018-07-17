'use strict';

const jwt = require('../');
const expect = require('chai').expect;
const util = require('util');

function signWithSubject(payload, subject) {
  const options = {algorithm: 'none'};
  if (subject !== undefined) {
    options.subject = subject;
  }
  return jwt.sign(payload, undefined, options);
}

describe('subject', function() {
  describe('`jwt.sign` "subject" option validation', function () {
    [
      true,
      false,
      null,
      -1,
      0,
      1,
      -1.1,
      1.1,
      -Infinity,
      Infinity,
      NaN,
      [],
      ['foo'],
      {},
      {foo: 'bar'},
    ].forEach((subject) => {
      it(`should error with with value ${util.inspect(subject)}`, function () {
        expect(() => signWithSubject({}, subject)).to.throw('"subject" must be a string');
      });
    });

    // undefined needs special treatment because {} is not the same as {subject: undefined}
    it('should error with with value undefined', function () {
      expect(() => jwt.sign({}, undefined, {subject: undefined, algorithm: 'none'})).to.throw(
        '"subject" must be a string'
      );
    });

    it('should error when "sub" is in payload', function () {
      expect(() => signWithSubject({sub: 'bar'}, 'foo')).to.throw(
        'Bad "options.subject" option. The payload already has an "sub" property.'
      );
    });


    it('should error with a string payload', function () {
      expect(() => signWithSubject('a string payload', 'foo')).to.throw(
        'invalid subject option for string payload'
      );
    });

    it('should error with a Buffer payload', function () {
      expect(() => signWithSubject(new Buffer('a Buffer payload'), 'foo')).to.throw(
        'invalid subject option for object payload'
      );
    });
  });

  describe('when signing and verifying a token with "subject" option', function () {
    it('should verify with a string "subject"', function () {
      const token = signWithSubject({}, 'foo');
      const decoded = jwt.decode(token);
      const verified = jwt.verify(token, undefined, {subject: 'foo'});
      expect(decoded).to.deep.equal(verified);
      expect(decoded.sub).to.equal('foo');
    });

    it('should verify with a string "sub"', function () {
      const token = signWithSubject({sub: 'foo'});
      const decoded = jwt.decode(token);
      const verified = jwt.verify(token, undefined, {subject: 'foo'});
      expect(decoded).to.deep.equal(verified);
      expect(decoded.sub).to.equal('foo');
    });

    it('should not verify "sub" if "verify.subject" option not provided', function() {
      const token = signWithSubject({sub: 'foo'});
      const decoded = jwt.decode(token);
      const verified = jwt.verify(token, undefined);
      expect(decoded).to.deep.equal(verified);
      expect(decoded.sub).to.equal('foo');
    });

    it('should error if "sub" does not match "verify.subject" option', function() {
      const token = signWithSubject({sub: 'foo'});
      expect(() => jwt.verify(token, undefined, {subject: 'bar'})).to.throw(
        jwt.JsonWebTokenError,
        'jwt subject invalid. expected: bar'
      );
    });

    it('should error without "sub" and with "verify.subject" option', function() {
      const token = signWithSubject({});
      expect(() => jwt.verify(token, undefined, {subject: 'foo'})).to.throw(
        jwt.JsonWebTokenError,
        'jwt subject invalid. expected: foo'
      );
    });
  });
});
