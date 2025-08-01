const jwt = require('../index');

describe('issue 304 - verifying values other than strings', () => {

  it('should fail with numbers', (done) => {
    jwt.verify(123, 'foo', (err) => {
      expect(err.name).toBe('JsonWebTokenError');
      done();
    });
  });

  it('should fail with objects', (done) => {
    jwt.verify({ foo: 'bar' }, 'biz', (err) => {
      expect(err.name).toBe('JsonWebTokenError');
      done();
    });
  });

  it('should fail with arrays', (done) => {
    jwt.verify(['foo'], 'bar', (err) => {
      expect(err.name).toBe('JsonWebTokenError');
      done();
    });
  });

  it('should fail with functions', (done) => {
    jwt.verify(() => {}, 'foo', (err) => {
      expect(err.name).toBe('JsonWebTokenError');
      done();
    });
  });

  it('should fail with booleans', (done) => {
    jwt.verify(true, 'foo', (err) => {
      expect(err.name).toBe('JsonWebTokenError');
      done();
    });
  });

});
