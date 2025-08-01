const jwt = require("../.");
const {assert} = require('chai');

describe('buffer payload', () => {
  it('should work', () => {
    const payload = new Buffer('TkJyotZe8NFpgdfnmgINqg==', 'base64');
    const token = jwt.sign(payload, "signing key");
    assert.equal(jwt.decode(token), payload.toString());
  });
});
