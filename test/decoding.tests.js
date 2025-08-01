const jwt = require('../index');

describe('decoding', () => {

  it('should not crash when decoding a null token', () => {
    const decoded = jwt.decode("null");
    expect(decoded).toBe(null);
  });

});
