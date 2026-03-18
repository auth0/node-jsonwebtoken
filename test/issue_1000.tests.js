'use strict';

const jwt = require('../');
const expect = require('chai').expect;

describe('issue 1000 - callback invocation count on payload property conflicts', function() {
  const secret = 'super-secret-key';

  describe('when payload already has a claim that conflicts with options', function() {
    const conflictingCases = [
      { option: 'issuer', claim: 'iss', optionValue: 'option-issuer', claimValue: 'payload-issuer' },
      { option: 'subject', claim: 'sub', optionValue: 'option-subject', claimValue: 'payload-subject' },
      { option: 'audience', claim: 'aud', optionValue: 'option-audience', claimValue: 'payload-audience' },
      { option: 'jwtid', claim: 'jti', optionValue: 'option-jwtid', claimValue: 'payload-jwtid' },
    ];

    conflictingCases.forEach(({ option, claim, optionValue, claimValue }) => {
      it(`should call callback exactly once when payload has "${claim}" and options has "${option}"`, function(done) {
        let callbackCount = 0;

        const payload = { data: 'test', [claim]: claimValue };
        const options = { [option]: optionValue, algorithm: 'HS256' };

        jwt.sign(payload, secret, options, function(err, token) {
          callbackCount++;

          // Use setImmediate to let any additional callbacks execute first
          setImmediate(function() {
            expect(callbackCount).to.equal(1, `Callback was called ${callbackCount} times, expected exactly 1`);
            expect(err).to.be.instanceOf(Error);
            expect(err.message).to.equal(`Bad "options.${option}" option. The payload already has an "${claim}" property.`);
            expect(token).to.be.undefined;
            done();
          });
        });
      });
    });

    it('should call callback exactly once with multiple conflicting options', function(done) {
      let callbackCount = 0;

      const payload = { data: 'test', iss: 'payload-issuer', sub: 'payload-subject' };
      const options = { issuer: 'option-issuer', subject: 'option-subject', algorithm: 'HS256' };

      jwt.sign(payload, secret, options, function(err, token) {
        callbackCount++;

        setImmediate(function() {
          expect(callbackCount).to.equal(1, `Callback was called ${callbackCount} times, expected exactly 1`);
          expect(err).to.be.instanceOf(Error);
          // Should error on the first conflict encountered (issuer)
          expect(err.message).to.equal('Bad "options.issuer" option. The payload already has an "iss" property.');
          expect(token).to.be.undefined;
          done();
        });
      });
    });
  });

  describe('when there are no payload property conflicts', function() {
    it('should call callback exactly once with a valid token', function(done) {
      let callbackCount = 0;

      const payload = { data: 'test' };
      const options = { issuer: 'my-issuer', algorithm: 'HS256' };

      jwt.sign(payload, secret, options, function(err, token) {
        callbackCount++;

        setImmediate(function() {
          expect(callbackCount).to.equal(1, `Callback was called ${callbackCount} times, expected exactly 1`);
          expect(err).to.be.null;
          expect(token).to.be.a('string');

          // Verify the token contains the expected claims
          const decoded = jwt.decode(token);
          expect(decoded.data).to.equal('test');
          expect(decoded.iss).to.equal('my-issuer');
          done();
        });
      });
    });

    it('should call callback exactly once when using all options_to_payload options', function(done) {
      let callbackCount = 0;

      const payload = { data: 'test' };
      const options = {
        issuer: 'my-issuer',
        subject: 'my-subject',
        audience: 'my-audience',
        jwtid: 'my-jwtid',
        algorithm: 'HS256'
      };

      jwt.sign(payload, secret, options, function(err, token) {
        callbackCount++;

        setImmediate(function() {
          expect(callbackCount).to.equal(1, `Callback was called ${callbackCount} times, expected exactly 1`);
          expect(err).to.be.null;
          expect(token).to.be.a('string');

          const decoded = jwt.decode(token);
          expect(decoded.iss).to.equal('my-issuer');
          expect(decoded.sub).to.equal('my-subject');
          expect(decoded.aud).to.equal('my-audience');
          expect(decoded.jti).to.equal('my-jwtid');
          done();
        });
      });
    });
  });

  describe('synchronous sign behavior', function() {
    it('should throw exactly once when payload has conflicting claim', function() {
      const payload = { data: 'test', iss: 'payload-issuer' };
      const options = { issuer: 'option-issuer', algorithm: 'HS256' };

      expect(() => jwt.sign(payload, secret, options))
        .to.throw('Bad "options.issuer" option. The payload already has an "iss" property.');
    });

    it('should return a valid token when there are no conflicts', function() {
      const payload = { data: 'test' };
      const options = { issuer: 'my-issuer', algorithm: 'HS256' };

      const token = jwt.sign(payload, secret, options);
      expect(token).to.be.a('string');

      const decoded = jwt.decode(token);
      expect(decoded.iss).to.equal('my-issuer');
    });
  });
});
