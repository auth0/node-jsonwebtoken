var jwt = require('../index');
var jws = require('jws');
var fs = require('fs');
var path = require('path');
var sinon = require('sinon');

var assert = require('chai').assert;

var equal = (first, second, last) => {
    var noCompare = ['iat', 'exp'];
    var areEqual = true;

    if (first.header) {
        var equalHeader = equal(first.header, second.header);
        var equalPayload = equal(first.payload, second.payload);
        areEqual = (equalHeader && equalPayload);
    }
    else {
        for (var key in first) {
            if (noCompare.indexOf(key) === -1) {
                console.log(key + ' -> ' + first[key] + ' : ' + second[key]);
                if (first[key] !== second[key]) {
                    areEqual = false;
                    break;
                }
            }
            else {
                //not caring about iat and exp
            }
        }
    }

    if (!last) {
        areEqual = equal(second, first, true);
    }

    return areEqual;
}

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
      var refreshed = jwt.refresh(jwt.decode(token, {complete: true}), 3600, secret);
    //   console.log(JSON.stringify(refreshed));
      assert.ok(refreshed);
      done();
  });

  it('Decoded version of a refreshed token should be the same, except for timing data', function (done) {
      var originalDecoded = jwt.decode(token, {complete: true});
      var refreshed = jwt.refresh(originalDecoded, 3600, secret);
      var refreshDecoded = jwt.decode(refreshed, {complete: true});

      var comparison = equal(originalDecoded, refreshDecoded);
      console.log('comparison : ' + comparison);

      assert.ok(comparison);
      assert.ok(refreshDecoded);

      //test that the refreshed token has a time in the future.
      done();
  });
});
