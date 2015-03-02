var jwt = require('../index');
var expect = require('chai').expect;
var atob = require('atob');

describe('encoding', function() {

  it('should properly encode the token', function () {
    var expected = '你好';
    var token = jwt.sign({ name: expected }, 'shhhhh');
    var decoded_name = JSON.parse(decodeURIComponent(escape(atob(token.split('.')[1])))).name;
    expect(decoded_name).to.equal(expected);
  });

});