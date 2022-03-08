var expect = require('chai').expect;

describe('encoding', function() {

  it('should import this module correctly', function () {
    return import('jsonwebtoken').then(jwt => {
      expect(jwt.sign).to.be.a('function');
      expect(jwt.decode).to.be.a('function');
      expect(jwt.verify).to.be.a('function');
      expect(jwt.JsonWebTokenError).to.be.a('function');
      expect(jwt.NotBeforeError).to.be.a('function');
      expect(jwt.TokenExpiredError).to.be.a('function');
    });
  });

});
