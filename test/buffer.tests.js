const jwt = require("../.");
const assert = require('chai').assert;

describe('buffer payload', function () {
  it('should work', function () {
    const payload = new Buffer('TkJyotZe8NFpgdfnmgINqg==', 'base64');
    const token = jwt.sign(payload, "signing key");
    assert.equal(jwt.decode(token), payload.toString());
  });
});
