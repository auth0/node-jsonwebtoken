var jwt = require('../');

describe('issue 70', function () {

  it('should work', function () {
    var fs = require('fs');
    var cert_pub = fs.readFileSync(__dirname + '/pub.pem');
    var cert_priv = fs.readFileSync(__dirname + '/priv.pem');

    var token = jwt.sign({ foo: 'bar' }, cert_priv, { algorithm: 'RS256'});

    jwt.verify(token, cert_pub, function(err, decoded) {
      console.log("Decoded: " + JSON.stringify(decoded));
      console.log("Error: " + err);
    });

  });
});