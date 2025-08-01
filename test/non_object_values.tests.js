const jwt = require('../index');

describe('non_object_values values', () => {

  it('should work with string', () => {
    const token = jwt.sign('hello', '123');
    const result = jwt.verify(token, '123');
    expect(result).toBe('hello');
  });

  it('should work with number', () => {
    const token = jwt.sign(123, '123');
    const result = jwt.verify(token, '123');
    expect(result).toBe('123');
  });

});
