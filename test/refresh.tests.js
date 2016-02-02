var jwt = require('../index');
var jws = require('jws');
var fs = require('fs');
var path = require('path');
var sinon = require('sinon');

var assert = require('chai').assert;

describe('Refresh Token Testing', function() {

    var secret = 'ssshhhh';
    var options = {
        algorithm: 'HS256',
        expiresIn: '3600',
        subject: 'Testing Refresh',
        issuer: 'node-jsonwebtoken',
        headers: {
            a: 'header'
        }
    };
    var payload = {
        scope: 'admin',
        something: 'else',
        more: 'payload'
    };

    var expectedPayloadNoHeader = {
        scope: 'admin',
        something: 'else',
        more: 'payload',
        expiresIn: '3600',
        subject: 'Testing Refresh',
        issuer: 'node-jsonwebtoken'
    }

    var token = jwt.sign(payload, secret, options);

  it('Should be able to verify token normally', function (done) {
    jwt.verify(token, secret, {typ: 'JWT'}, function(err, p) {
        assert.isNull(err);
        done();
    });
  });

  it('Should be able to decode the token (proof of good token)', function (done) {
      var decoded = jwt.decode(token, {complete: true});
      assert.ok(decoded.payload.scope);
      assert.equal('admin', decoded.payload.scope);
      done();
  });

  it('Should be able to refresh the token', function (done) {
      var refreshed = jwt.refresh(token, 3600, secret);
      console.log(JSON.stringify(refreshed));
      assert.ok(refreshed);
      done();
  });
});
