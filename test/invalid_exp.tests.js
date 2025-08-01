const jwt = require('../index');

describe('invalid expiration', () => {

  it('should fail with string', (done) => {
    const broken_token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOiIxMjMiLCJmb28iOiJhZGFzIn0.cDa81le-pnwJMcJi3o3PBwB7cTJMiXCkizIhxbXAKRg';

    jwt.verify(broken_token, '123', (err) => {
      expect(err.name).toBe('JsonWebTokenError');
      done();
    });

  });

  it('should fail with 0', (done) => {
    const broken_token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjAsImZvbyI6ImFkYXMifQ.UKxix5T79WwfqAA0fLZr6UrhU-jMES2unwCOFa4grEA';

    jwt.verify(broken_token, '123', (err) => {
      expect(err.name).toBe('TokenExpiredError');
      done();
    });

  });

  it('should fail with false', (done) => {
    const broken_token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOmZhbHNlLCJmb28iOiJhZGFzIn0.iBn33Plwhp-ZFXqppCd8YtED77dwWU0h68QS_nEQL8I';

    jwt.verify(broken_token, '123', (err) => {
      expect(err.name).toBe('JsonWebTokenError');
      done();
    });

  });

  it('should fail with true', (done) => {
    const broken_token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOnRydWUsImZvbyI6ImFkYXMifQ.eOWfZCTM5CNYHAKSdFzzk2tDkPQmRT17yqllO-ItIMM';

    jwt.verify(broken_token, '123', (err) => {
      expect(err.name).toBe('JsonWebTokenError');
      done();
    });

  });

  it('should fail with object', (done) => {
    const broken_token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOnt9LCJmb28iOiJhZGFzIn0.1JjCTsWLJ2DF-CfESjLdLfKutUt3Ji9cC7ESlcoBHSY';

    jwt.verify(broken_token, '123', (err) => {
      expect(err.name).toBe('JsonWebTokenError');
      done();
    });

  });


});