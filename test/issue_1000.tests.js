'use strict';

const jwt = require('../');
const expect = require('chai').expect;

describe('issue 1000 - callback executed twice on payload conflict', function() {
  it('should call the callback only once when payload has conflicting "iss" property', function(done) {
    let callCount = 0;

    jwt.sign(
      { iss: 'bar', iat: 1757476476 },
      'secret',
      { algorithm: 'HS256', issuer: 'foo' },
      (err, token) => {
        callCount++;

        // The callback should only be called once
        if (callCount > 1) {
          done(new Error(`Callback was called ${callCount} times instead of once`));
          return;
        }

        // Give time for potential second callback
        setTimeout(() => {
          expect(callCount).to.equal(1);
          expect(err).to.be.instanceOf(Error);
          expect(err.message).to.equal('Bad "options.issuer" option. The payload already has an "iss" property.');
          expect(token).to.be.undefined;
          done();
        }, 50);
      }
    );
  });

  it('should call the callback only once when payload has conflicting "sub" property', function(done) {
    let callCount = 0;

    jwt.sign(
      { sub: 'bar' },
      'secret',
      { algorithm: 'HS256', subject: 'foo' },
      (err, token) => {
        callCount++;

        if (callCount > 1) {
          done(new Error(`Callback was called ${callCount} times instead of once`));
          return;
        }

        setTimeout(() => {
          expect(callCount).to.equal(1);
          expect(err).to.be.instanceOf(Error);
          expect(err.message).to.equal('Bad "options.subject" option. The payload already has an "sub" property.');
          expect(token).to.be.undefined;
          done();
        }, 50);
      }
    );
  });

  it('should call the callback only once when payload has conflicting "aud" property', function(done) {
    let callCount = 0;

    jwt.sign(
      { aud: 'bar' },
      'secret',
      { algorithm: 'HS256', audience: 'foo' },
      (err, token) => {
        callCount++;

        if (callCount > 1) {
          done(new Error(`Callback was called ${callCount} times instead of once`));
          return;
        }

        setTimeout(() => {
          expect(callCount).to.equal(1);
          expect(err).to.be.instanceOf(Error);
          expect(err.message).to.equal('Bad "options.audience" option. The payload already has an "aud" property.');
          expect(token).to.be.undefined;
          done();
        }, 50);
      }
    );
  });

  it('should call the callback only once when payload has conflicting "jti" property', function(done) {
    let callCount = 0;

    jwt.sign(
      { jti: 'bar' },
      'secret',
      { algorithm: 'HS256', jwtid: 'foo' },
      (err, token) => {
        callCount++;

        if (callCount > 1) {
          done(new Error(`Callback was called ${callCount} times instead of once`));
          return;
        }

        setTimeout(() => {
          expect(callCount).to.equal(1);
          expect(err).to.be.instanceOf(Error);
          expect(err.message).to.equal('Bad "options.jwtid" option. The payload already has an "jti" property.');
          expect(token).to.be.undefined;
          done();
        }, 50);
      }
    );
  });
});
