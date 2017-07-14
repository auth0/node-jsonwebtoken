var sign = require('./sign');
var verify = require('./verify');
var decode = require('./decode');

/**
* Will refresh the given token.  The token is expected to be decoded and valid. No checks will be
* performed on the token.  The function will copy the values of the token, give it a new
* expiry time based on the given 'expiresIn' time and will return a new signed token.
*
* @param token
* @param expiresIn
* @param secretOrPrivateKey
* @param verifyOptions - Options to verify the token
* @param callback
* @return New signed JWT token
*/
module.exports = function(token, expiresIn, secretOrPrivateKey, verifyOptions, callback) {
    //TODO: check if token is not good, if so return error ie: no payload, not required fields, etc.

    var done;
    if (callback) {
        done = function() {

            var args = Array.prototype.slice.call(arguments, 0);
            return process.nextTick(function() {

                callback.apply(null, args);
            });
        };
    }
    else {
        done = function(err, data) {

            if (err) {
                console.log('err : ' + err);
                throw err;
            }
            return data;
        };
    }

    var verified;
    var header;
    var payload;
    var decoded = decode(token, {complete: true});

    try {
        verified = verify(token, secretOrPrivateKey, verifyOptions);
    }
    catch (error) {
        verified = null;
    }

    if (verified) {
        if (decoded.header) {
            header = decoded['header'];
            payload = decoded['payload'];
        }
        else {
            payload = token;
        }

        var optionMapping = {
            exp: 'expiresIn',
            aud: 'audience',
            nbf: 'notBefore',
            iss: 'issuer',
            sub: 'subject',
            jti: 'jwtid',
            alg: 'algorithm'
        };
        var newToken;
        var obj = {};
        var options = {};

        for (var key in payload) {
            if (Object.keys(optionMapping).indexOf(key) === -1) {
                obj[key] = payload[key];
            }
            else {
                options[optionMapping[key]] = payload[key];
            }
        }

        if(header) {
            options.header = { };
            for (var key in header) {
                if (key !== 'typ') {    //don't care about typ -> always JWT
                    if (Object.keys(optionMapping).indexOf(key) === -1) {
                        options.header[key] = header[key];
                    }
                    else {
                        options[optionMapping[key]] = header[key];
                    }
                }
            }
        }
        else {
            console.log('No algorithm was defined for token refresh - using default');
        }

        if (!token.iat) {
            options['noTimestamp'] = true;
        }

        options['expiresIn'] = expiresIn;

        newToken = sign(obj, secretOrPrivateKey, options);
        return done(null, newToken);
    }
    else {
        return done('Token invalid.  Failed to verify.');
    }
};
