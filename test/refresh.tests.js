var jwt = require('../index');
var jws = require('jws');
var fs = require('fs');
var path = require('path');
var sinon = require('sinon');

var assert = require('chai').assert;

/**
* Method to verify if first token is euqal to second token.  This is a symmetric
* test.  Will check that first = second, and that second = first.
*
* All properties are tested, except for the 'iat' and 'exp' values since we do not
* care for those as we are expecting them to be different.
*
* @param first - The first decoded token
* @param second - The second decoded token
* @param last - boolean value to state that this is the last test and no need to rerun
*               the symmetric test.
* @return boolean - true if the tokens match.
*/
var equal = function (first, second, last) {
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
      assert.ok(refreshed);
      done();
  });

  it('Should be able to refresh the token (async)', function (done) {
      var refreshed = jwt.refresh(jwt.decode(token, {complete: true}), 3600, secret, function(err, refreshedToken) {
          assert.ok(refreshedToken);
      });
      done();
  });

  var originalDecoded = jwt.decode(token, {complete: true});
  var refreshed = jwt.refresh(originalDecoded, 3600, secret);
  var refreshDecoded = jwt.decode(refreshed, {complete: true});
  var refreshAsync;
  var refreshAsyncDecoded;
  jwt.refresh(jwt.decode(token, {complete: true}), 3600, secret, function(err, refreshedToken) {
      refreshAsync = refreshedToken;
      refreshAsyncDecoded = jwt.decode(refreshed, {complete: true});
  });

  it('Sub-test to ensure that the compare method works', function (done) {
      var originalMatch = equal(originalDecoded, originalDecoded);
      var refreshMatch = equal(refreshDecoded, refreshDecoded);
      var asyncRefreshMatch = equal(originalDecoded, refreshAsyncDecoded);

      assert.equal(originalMatch, refreshMatch);
      assert.equal(originalMatch, asyncRefreshMatch);
      done();
  });

  it('Decoded version of a refreshed token should be the same, except for timing data', function (done) {
      var comparison = equal(originalDecoded, refreshDecoded);
      var asyncComparison = equal(originalDecoded, refreshAsyncDecoded);

      assert.ok(comparison);
      assert.ok(asyncComparison);
      done();
  });

  it('Refreshed token should have a later expiery time then the original', function (done) {
      var originalExpiry = originalDecoded.payload.exp;
      var refreshedExpiry = refreshDecoded.payload.exp;
      var refreshedAsyncExpiry = refreshAsyncDecoded.payload.exp;

      assert.isTrue((refreshedExpiry > originalExpiry), 'Refreshed expiry time is above original time');
      assert.isTrue((refreshedAsyncExpiry > originalExpiry), 'Refreshed expiry time is above original time (async)');
      done();
  });

  it('Refreshing a token that\'s is not from an original decoded token should still work - basically creating a brand new token', function (done) {
      var notReallyAToken = {
          key: 'value',
          foo: 'bar',
          not: 'a token'
      }
      var notReallyATokenRefresh = jwt.refresh(notReallyAToken, 3600, secret);

      assert.ok(notReallyATokenRefresh);
      done();
  });

  it('Should fail when not providing a time value for the expiresIn value', function (done) {
      var notReallyAToken = {
          key: 'value',
          foo: 'bar',
          not: 'a token'
      }

      var failRefresh;
      try {
          var failRefresh = jwt.refresh(notReallyAToken, null, secret);
      } catch (err) {
          assert.equal(err.name, 'Error');
          assert.equal(err.message, '"expiresIn" should be a number of seconds or string representing a timespan eg: "1d", "20h", 60');
      }

      assert.notOk(failRefresh);
      done();
  });
});
