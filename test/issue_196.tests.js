var expect = require('chai').expect;
var jwt = require('./..');
var atob = require('atob');

describe('issue 196', function () {
  function b64_to_utf8 (str) {
    return decodeURIComponent(escape(atob( str )));
  }

  it('should use issuer provided in payload.iss', function () {
    var token = jwt.sign({ iss: 'foo' }, 'shhhhh');
    var decoded_issuer = JSON.parse(b64_to_utf8(token.split('.')[1])).iss;
    expect(decoded_issuer).to.equal('foo');
  });
});
