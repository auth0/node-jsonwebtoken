var jwt = require('../index');
var JsonWebTokenError = require('../lib/JsonWebTokenError');
var TokenExpiredError = require('../lib/TokenExpiredError');
var expect = require('chai').expect;
var assert = require('chai').assert;

describe('invalid expiration', function() {

  it('should fail with string', function () {
    var broken_token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOiIxMjMiLCJmb28iOiJhZGFzIn0.cDa81le-pnwJMcJi3o3PBwB7cTJMiXCkizIhxbXAKRg';
    var verify = jwt.verify.bind(null, broken_token, '123');
    expect(verify).to.throw(JsonWebTokenError);
  });

  it('should fail with 0', function () {
    var broken_token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjAsImZvbyI6ImFkYXMifQ.UKxix5T79WwfqAA0fLZr6UrhU-jMES2unwCOFa4grEA';
    var verify = jwt.verify.bind(null, broken_token, '123');
    expect(verify).to.throw(TokenExpiredError);
  });

  it('should fail with false', function () {
    var broken_token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOmZhbHNlLCJmb28iOiJhZGFzIn0.iBn33Plwhp-ZFXqppCd8YtED77dwWU0h68QS_nEQL8I';
    var verify = jwt.verify.bind(null, broken_token, '123');
    expect(verify).to.throw(JsonWebTokenError);
  });

  it('should fail with true', function () {
    var broken_token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOnRydWUsImZvbyI6ImFkYXMifQ.eOWfZCTM5CNYHAKSdFzzk2tDkPQmRT17yqllO-ItIMM';
    var verify = jwt.verify.bind(null, broken_token, '123');
    expect(verify).to.throw(JsonWebTokenError);
  });

  it('should fail with object', function () {
    var broken_token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOnt9LCJmb28iOiJhZGFzIn0.1JjCTsWLJ2DF-CfESjLdLfKutUt3Ji9cC7ESlcoBHSY';
    var verify = jwt.verify.bind(null, broken_token, '123');
    expect(verify).to.throw(JsonWebTokenError);
  });

});
