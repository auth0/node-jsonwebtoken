'use strict';

const jwt = require('../');
const expect = require('chai').expect;
const util = require('util');

function signWithAudience(payload, audience) {
  const options = {algorithm: 'none'};
  if (audience !== undefined) {
    options.audience = audience;
  }
  return jwt.sign(payload, undefined, options);
}

describe('audience', function() {
  describe('`jwt.sign` "audience" option validation', function () {
    [
      true,
      false,
      null,
      -1,
      1,
      0,
      -1.1,
      1.1,
      -Infinity,
      Infinity,
      NaN,
      {},
      {foo: 'bar'},
    ].forEach((audience) => {
      it(`should error with with value ${util.inspect(audience)}`, function () {
        expect(() => signWithAudience({}, audience)).to.throw('"audience" must be a string or array');
      });
    });

    // undefined needs special treatment because {} is not the same as {aud: undefined}
    it('should error with with value undefined', function () {
      expect(() => jwt.sign({}, undefined, {audience: undefined, algorithm: 'none'})).to.throw(
        '"audience" must be a string or array'
      );
    });

    it('should error when "aud" is in payload', function () {
      expect(() => signWithAudience({aud: ''}, 'my_aud')).to.throw(
        'Bad "options.audience" option. The payload already has an "aud" property.'
      );
    });

    it('should error with a string payload', function () {
      expect(() => signWithAudience('a string payload', 'my_aud')).to.throw(
        'invalid audience option for string payload'
      );
    });

    it('should error with a Buffer payload', function () {
      expect(() => signWithAudience(new Buffer('a Buffer payload'), 'my_aud')).to.throw(
        'invalid audience option for object payload'
      );
    });
  });

  describe('when signing and verifying a token with "audience" option', function () {
    describe('with a string for "aud" value in payload', function () {
      let token;

      beforeEach(function () {
        token = signWithAudience({}, 'urn:foo');
      });

      it('should verify and decode without verify "audience" option', function () {
        const decoded = jwt.decode(token);
        const verified = jwt.verify(token, undefined);

        expect(decoded).to.deep.equal(verified);
        expect(decoded.aud).to.equal('urn:foo');
      });

      it('should verify with a string "verify.audience" option', function () {
        expect(jwt.verify(token, undefined, {
          audience: 'urn:foo'
        })).to.not.throw;
      });

      it('should verify with an array of strings "verify.audience" option', function () {
        expect(jwt.verify(token, undefined, {
          audience: ['urn:no_match', 'urn:foo']
        })).to.not.throw;
      });

      it('should verify with a Regex "verify.audience" option', function () {
        expect(jwt.verify(token, undefined, {
          audience: /^urn:f[o]{2}$/
        })).to.not.throw;
      });

      it('should verify with an array of Regex "verify.audience" option', function () {
        expect(jwt.verify(token, undefined, {
          audience: [/^urn:no_match$/, /^urn:f[o]{2}$/]
        })).to.not.throw;
      });

      it('should verify with an array containing a string and a Regex "verify.audience" option', function () {
        expect(jwt.verify(token, undefined, {
          audience: ['urn:no_match', /^urn:f[o]{2}$/]
        })).to.not.throw;
      });

      it('should verify with an array containing a Regex and a string "verify.audience" option', function () {
        expect(jwt.verify(token, undefined, {
          audience: [/^urn:no_match$/, 'urn:foo']
        })).to.not.throw;
      });

      it('should error on no match with a string "verify.audience" option', function () {
        expect(() => jwt.verify(token, undefined, {
          audience: 'urn:no-match'
        })).to.throw(jwt.JsonWebTokenError, 'jwt audience invalid. expected: urn:no-match');
      });

      it('should error on no match with an array of string "verify.audience" option', function () {
        expect(() => jwt.verify(token, undefined, {
          audience: ['urn:no-match-1', 'urn:no-match-2']
        })).to.throw(jwt.JsonWebTokenError, 'jwt audience invalid. expected: urn:no-match-1 or urn:no-match-2');
      });

      it('should error on no match with a Regex "verify.audience" option', function () {
        expect(() => jwt.verify(token, undefined, {
          audience: /^urn:no-match$/
        })).to.throw(jwt.JsonWebTokenError, 'jwt audience invalid. expected: /^urn:no-match$/');
      });

      it('should error on no match with an array of Regex "verify.audience" option', function () {
        expect(() => jwt.verify(token, undefined, {
          audience: [/^urn:no-match-1$/, /^urn:no-match-2$/]
        })).to.throw(jwt.JsonWebTokenError, 'jwt audience invalid. expected: /^urn:no-match-1$/ or /^urn:no-match-2$/');
      });

      it('should error on no match with an array of a Regex and a string in "verify.audience" option', function () {
        expect(() => jwt.verify(token, undefined, {
          audience: [/^urn:no-match$/, 'urn:no-match']
        })).to.throw(jwt.JsonWebTokenError, 'jwt audience invalid. expected: /^urn:no-match$/ or urn:no-match');
      });
    });

    describe('with an array for "aud" value in payload', function () {
      let token;

      beforeEach(function () {
        token = signWithAudience({}, ['urn:foo', 'urn:bar']);
      });

      it('should verify and decode without verify "audience" option', function () {
        const decoded = jwt.decode(token);
        const verified = jwt.verify(token, undefined);

        expect(decoded).to.deep.equal(verified);
        expect(decoded.aud).to.deep.equal(['urn:foo', 'urn:bar']);
      });

      it('should error on no match with a string "verify.audience" option', function () {
        expect(() => jwt.verify(token, undefined, {
          audience: 'urn:no-match'
        })).to.throw(jwt.JsonWebTokenError, 'jwt audience invalid. expected: urn:no-match');
      });

      it('should error on no match with an array of string "verify.audience" option', function () {
        expect(() => jwt.verify(token, undefined, {
          audience: ['urn:no-match-1', 'urn:no-match-2']
        })).to.throw(jwt.JsonWebTokenError, 'jwt audience invalid. expected: urn:no-match-1 or urn:no-match-2');
      });

      it('should error on no match with a Regex "verify.audience" option', function () {
        expect(() => jwt.verify(token, undefined, {
          audience: /^urn:no-match$/
        })).to.throw(jwt.JsonWebTokenError, 'jwt audience invalid. expected: /^urn:no-match$/');
      });

      it('should error on no match with an array of Regex "verify.audience" option', function () {
        expect(() => jwt.verify(token, undefined, {
          audience: [/^urn:no-match-1$/, /^urn:no-match-2$/]
        })).to.throw(jwt.JsonWebTokenError, 'jwt audience invalid. expected: /^urn:no-match-1$/ or /^urn:no-match-2$/');
      });

      it('should error on no match with an array of a Regex and a string in "verify.audience" option', function () {
        expect(() => jwt.verify(token, undefined, {
          audience: [/^urn:no-match$/, 'urn:no-match']
        })).to.throw(jwt.JsonWebTokenError, 'jwt audience invalid. expected: /^urn:no-match$/ or urn:no-match');
      });

      describe('when checking matching for both "urn:foo" and "urn:bar"', function() {

        it('should verify with an array of stings "verify.audience" option', function () {
          expect(jwt.verify(token, undefined, {
            audience: ['urn:foo', 'urn:bar']
          })).to.not.throw;
        });

        it('should verify with a Regex "verify.audience" option', function () {
          expect(jwt.verify(token, undefined, {
            audience: /^urn:[a-z]{3}$/
          })).to.not.throw;
        });

        it('should verify with an array of Regex "verify.audience" option', function () {
          expect(jwt.verify(token, undefined, {
            audience: [/^urn:f[o]{2}$/, /^urn:b[ar]{2}$/]
          })).to.not.throw;
        });
      });

      describe('when checking for a matching for "urn:foo"', function() {
        it('should verify with a string "verify.audience"', function () {
          expect(jwt.verify(token, undefined, {
            audience: 'urn:foo'
          })).to.not.throw;
        });

        it('should verify with a Regex "verify.audience" option', function () {
          expect(jwt.verify(token, undefined, {
            audience: /^urn:f[o]{2}$/
          })).to.not.throw;
        });

        it('should verify with an array of Regex "verify.audience"', function () {
          expect(jwt.verify(token, undefined, {
            audience: [/^urn:no-match$/, /^urn:f[o]{2}$/]
          })).to.not.throw;
        });

        it('should verify with an array containing a string and a Regex "verify.audience" option', function () {
          expect(jwt.verify(token, undefined, {
            audience: ['urn:no_match', /^urn:f[o]{2}$/]
          })).to.not.throw;
        });

        it('should verify with an array containing a Regex and a string "verify.audience" option', function () {
          expect(jwt.verify(token, undefined, {
            audience: [/^urn:no-match$/, 'urn:foo']
          })).to.not.throw;
        });
      });

      describe('when checking matching for "urn:bar"', function() {
        it('should verify with a string "verify.audience"', function () {
          expect(jwt.verify(token, undefined, {
            audience: 'urn:bar'
          })).to.not.throw;
        });

        it('should verify with a Regex "verify.audience" option', function () {
          expect(jwt.verify(token, undefined, {
            audience: /^urn:b[ar]{2}$/
          })).to.not.throw;
        });

        it('should verify with an array of Regex "verify.audience" option', function () {
          expect(jwt.verify(token, undefined, {
            audience: [/^urn:no-match$/, /^urn:b[ar]{2}$/]
          })).to.not.throw;
        });

        it('should verify with an array containing a string and a Regex "verify.audience" option', function () {
          expect(jwt.verify(token, undefined, {
            audience: ['urn:no_match', /^urn:b[ar]{2}$/]
          })).to.not.throw;
        });

        it('should verify with an array containing a Regex and a string "verify.audience" option', function () {
          expect(jwt.verify(token, undefined, {
            audience: [/^urn:no-match$/, 'urn:bar']
          })).to.not.throw;
        });
      });
    });

    describe('without a "aud" value in payload', function () {
      let token;

      beforeEach(function () {
        token = signWithAudience({});
      });

      it('should verify and decode without verify "audience" option', function () {
        const decoded = jwt.decode(token);
        const verified = jwt.verify(token, undefined);

        expect(decoded).to.deep.equal(verified);
        expect(decoded).to.not.have.property('aud');
      });

      it('should error on no match with a string "verify.audience" option', function () {
        expect(() => jwt.verify(token, undefined, {
          audience: 'urn:no-match'
        })).to.throw(jwt.JsonWebTokenError, 'jwt audience invalid. expected: urn:no-match');
      });

      it('should error on no match with an array of string "verify.audience" option', function () {
        expect(() => jwt.verify(token, undefined, {
          audience: ['urn:no-match-1', 'urn:no-match-2']
        })).to.throw(jwt.JsonWebTokenError, 'jwt audience invalid. expected: urn:no-match-1 or urn:no-match-2');
      });

      it('should error on no match with a Regex "verify.audience" option', function () {
        expect(() => jwt.verify(token, undefined, {
          audience: /^urn:no-match$/
        })).to.throw(jwt.JsonWebTokenError, 'jwt audience invalid. expected: /^urn:no-match$/');
      });

      it('should error on no match with an array of Regex "verify.audience" option', function () {
        expect(() => jwt.verify(token, undefined, {
          audience: [/^urn:no-match-1$/, /^urn:no-match-2$/]
        })).to.throw(jwt.JsonWebTokenError, 'jwt audience invalid. expected: /^urn:no-match-1$/ or /^urn:no-match-2$/');
      });

      it('should error on no match with an array of a Regex and a string in "verify.audience" option', function () {
        expect(() => jwt.verify(token, undefined, {
          audience: [/^urn:no-match$/, 'urn:no-match']
        })).to.throw(jwt.JsonWebTokenError, 'jwt audience invalid. expected: /^urn:no-match$/ or urn:no-match');
      });
    });
  });
});
