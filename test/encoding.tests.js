const jwt = require('../index');
const expect = require('chai').expect;
const atob = require('atob');

describe('encoding', function() {

  function b64_to_utf8 (str) {
    return decodeURIComponent(escape(atob( str )));
  }

  it('should properly encode the token (utf8)', function () {
    const expected = 'José';
    const token = jwt.sign({ name: expected }, 'shhhhh');
    const decoded_name = JSON.parse(b64_to_utf8(token.split('.')[1])).name;
    expect(decoded_name).to.equal(expected);
  });

  it('should properly encode the token (binary)', function () {
    const expected = 'José';
    const token = jwt.sign({ name: expected }, 'shhhhh', { encoding: 'binary' });
    const decoded_name = JSON.parse(atob(token.split('.')[1])).name;
    expect(decoded_name).to.equal(expected);
  });

  it('should return the same result when decoding', function () {
    const username = '測試';

    const token = jwt.sign({
      username: username
    }, 'test');

    const payload = jwt.verify(token, 'test');

    expect(payload.username).to.equal(username);
  });

});
