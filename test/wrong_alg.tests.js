var fs = require('fs');
var path = require('path');
var jwt = require('../index');
var JsonWebTokenError = require('../lib/JsonWebTokenError');
var expect = require('chai').expect;


var pub = fs.readFileSync(path.join(__dirname, 'pub.pem'), 'utf8');
// priv is never used
// var priv = fs.readFileSync(path.join(__dirname, 'priv.pem'));

var TOKEN = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE0MjY1NDY5MTl9.ETgkTn8BaxIX4YqvUWVFPmum3moNZ7oARZtSBXb_vP4';

describe('signing with pub key as symmetric', function () {
  it('should not verify', function () {
    expect(function () {
      jwt.verify(TOKEN, pub);
    }).to.throw(JsonWebTokenError, /invalid signature/);
  });
});