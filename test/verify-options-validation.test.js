'use strict';

const jwt = require('../');
const expect = require('chai').expect;

const SECRET = 'secret';
const NOW = 1700000000;

function expiredToken() {
  return jwt.sign({ exp: NOW - 60 }, SECRET, { noTimestamp: true });
}

function notYetValidToken() {
  return jwt.sign({ nbf: NOW + 600 }, SECRET, { noTimestamp: true });
}

describe('verify: validación de opciones (HU-01, HU-02, HU-03)', function () {
  describe('HU-01 "clockTolerance" debe ser un número finito', function () {
    ['abc', '3600', Infinity, -Infinity, NaN, {}, [], true].forEach(function (value) {
      it('rechaza un token vencido con clockTolerance de ' + String(typeof value === 'object' ? JSON.stringify(value) : value), function () {
        expect(function () {
          jwt.verify(expiredToken(), SECRET, { clockTimestamp: NOW, clockTolerance: value });
        }).to.throw(jwt.JsonWebTokenError, 'clockTolerance must be a finite number');
      });
    });

    it('reporta el error por callback y no lo lanza', function (done) {
      jwt.verify(expiredToken(), SECRET, { clockTimestamp: NOW, clockTolerance: 'abc' }, function (err, decoded) {
        expect(err).to.be.instanceOf(jwt.JsonWebTokenError);
        expect(err.message).to.equal('clockTolerance must be a finite number');
        expect(decoded).to.equal(undefined);
        done();
      });
    });

    it('conserva el comportamiento con un número válido', function () {
      expect(jwt.verify(expiredToken(), SECRET, { clockTimestamp: NOW, clockTolerance: 120 })).to.have.property('exp', NOW - 60);
      expect(function () {
        jwt.verify(expiredToken(), SECRET, { clockTimestamp: NOW, clockTolerance: 10 });
      }).to.throw(jwt.TokenExpiredError);
    });
  });

  describe('HU-02 "ignoreExpiration" e "ignoreNotBefore" deben ser booleanos', function () {
    ['false', 'true', 0, 1, {}, []].forEach(function (value) {
      it('rechaza ignoreExpiration de ' + JSON.stringify(value), function () {
        expect(function () {
          jwt.verify(expiredToken(), SECRET, { clockTimestamp: NOW, ignoreExpiration: value });
        }).to.throw(jwt.JsonWebTokenError, 'ignoreExpiration must be a boolean');
      });

      it('rechaza ignoreNotBefore de ' + JSON.stringify(value), function () {
        expect(function () {
          jwt.verify(notYetValidToken(), SECRET, { clockTimestamp: NOW, ignoreNotBefore: value });
        }).to.throw(jwt.JsonWebTokenError, 'ignoreNotBefore must be a boolean');
      });
    });

    it('conserva el comportamiento con booleanos o sin la opción', function () {
      expect(jwt.verify(expiredToken(), SECRET, { clockTimestamp: NOW, ignoreExpiration: true })).to.have.property('exp');
      expect(jwt.verify(notYetValidToken(), SECRET, { clockTimestamp: NOW, ignoreNotBefore: true })).to.have.property('nbf');
      expect(function () {
        jwt.verify(expiredToken(), SECRET, { clockTimestamp: NOW, ignoreExpiration: false });
      }).to.throw(jwt.TokenExpiredError);
      expect(function () {
        jwt.verify(expiredToken(), SECRET, { clockTimestamp: NOW });
      }).to.throw(jwt.TokenExpiredError);
    });
  });

  describe('HU-03 opciones desconocidas no se ignoran en silencio', function () {
    ['algoritms', 'ignoreExpiracion', 'expiresIn'].forEach(function (name) {
      it('rechaza la opción desconocida "' + name + '"', function () {
        const options = {};
        options[name] = ['HS512'];
        expect(function () {
          jwt.verify(jwt.sign({ a: 1 }, SECRET), SECRET, options);
        }).to.throw(jwt.JsonWebTokenError, '"' + name + '" is not an allowed option');
      });
    });

    it('acepta todas las opciones documentadas de verify', function () {
      const token = jwt.sign({ a: 1, nonce: 'n1' }, SECRET, { audience: 'aud', issuer: 'iss', subject: 'sub', jwtid: 'jid' });
      const decoded = jwt.verify(token, SECRET, {
        algorithms: ['HS256'], audience: 'aud', issuer: 'iss', subject: 'sub', jwtid: 'jid',
        complete: false, ignoreExpiration: false, ignoreNotBefore: false, clockTolerance: 5,
        maxAge: '1h', nonce: 'n1', clockTimestamp: Math.floor(Date.now() / 1000), allowInvalidAsymmetricKeyTypes: false
      });
      expect(decoded).to.have.property('a', 1);
    });
  });
});
