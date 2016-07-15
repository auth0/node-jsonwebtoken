var jwt = require("../.");
var assert = require('chai').assert;

describe('buffer payload', function () {
  it('should work', function () {
    var payload = new Buffer('TkJyotZe8NFpgdfnmgINqg==', 'base64');
    var token = jwt.sign(payload, "signing key");
    assert.equal(jwt.decode(token), payload.toString());
  });
});
