var jwt = require('../index');

var claims = {"name": "doron", "age": 46};
jwt.sign(claims, 'secret', {"keyid": "1234"}, function(err, good) {
    console.log(jwt.decode(good, {"complete": true}).header.kid);
    jwt.verify(good, 'secret', function(err, result) {
        console.log(result);
    })
});
