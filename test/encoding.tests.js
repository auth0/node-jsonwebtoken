const jwt = require('../index');
const atob = require('atob');

describe('encoding', () => {

  function b64_to_utf8 (str) {
    return decodeURIComponent(escape(atob( str )));
  }

  it('should properly encode the token (utf8)', () => {
    const expected = 'José';
    const token = jwt.sign({ name: expected }, 'shhhhh');
    const decoded_name = JSON.parse(b64_to_utf8(token.split('.')[1])).name;
    expect(decoded_name).toBe(expected);
  });

  it('should properly encode the token (binary)', () => {
    const expected = 'José';
    const token = jwt.sign({ name: expected }, 'shhhhh', { encoding: 'binary' });
    const decoded_name = JSON.parse(atob(token.split('.')[1])).name;
    expect(decoded_name).toBe(expected);
  });

  it('should return the same result when decoding', () => {
    const username = '測試';

    const token = jwt.sign({
      username
    }, 'test');

    const payload = jwt.verify(token, 'test');

    expect(payload.username).toBe(username);
  });

});
