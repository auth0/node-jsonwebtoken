const jwt = require('../index');
const jws = require('jws');
const fs = require('fs');
const path = require('path');
const JsonWebTokenError = require('../lib/JsonWebTokenError');


describe('verify', () => {
  const pub = fs.readFileSync(path.join(__dirname, 'pub.pem'));
  const priv = fs.readFileSync(path.join(__dirname, 'priv.pem'));

  it('should first assume JSON claim set', async () => {
    const header = { alg: 'RS256' };
    const payload = { iat: Math.floor(Date.now() / 1000 ) };

    const signed = jws.sign({
      header,
      payload,
      secret: priv,
      encoding: 'utf8'
    });

    const p = await jwt.verify(signed, pub, {typ: 'JWT'});
    expect(p).toEqual(payload);
  });


  it('should not mutate options', async () => {
    const header = { alg: 'HS256' };
    const payload = { iat: Math.floor(Date.now() / 1000 ) };
    const  options = { typ: 'JWT' };
    const signed = jws.sign({
      header,
      payload,
      secret: 'secret',
      encoding: 'utf8'
    });

    await jwt.verify(signed, 'secret', options);
    expect(Object.keys(options).length).toEqual(1);
  });

  describe('secret or token as callback', () => {
    const token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE0MzcwMTg1ODIsImV4cCI6MTQzNzAxODU5Mn0.3aR3vocmgRpG05rsI9MpR6z2T_BGtMQaPq2YR6QaroU';
    const key = 'key';

    const payload = { foo: 'bar', iat: 1437018582, exp: 1437018592 };
    const options = {algorithms: ['HS256'], ignoreExpiration: true};

    it('without callback', async () => {
      const p = await jwt.verify(token, key, options);
      expect(p).toEqual(payload);
    });

    it('simple callback', async () => {
      const keyFunc = async function(header) {
        expect(header).toEqual({ alg: 'HS256', typ: 'JWT' });
        return key;
      };

      const p = await jwt.verify(token, keyFunc, options);
      expect(p).toEqual(payload);
    });

    it('should work with async key function', async () => {
      const keyFunc = async function(header) {
        return key;
      };

      const p = await jwt.verify(token, keyFunc, options);
      expect(p).toEqual(payload);
    });

    it('simple error', async () => {
      const keyFunc = async function(header) {
        throw new Error('key not found');
      };

      await expect(jwt.verify(token, keyFunc, options)).rejects.toThrow('key not found');
    });

    it('delayed callback', async () => {
      const keyFunc = async function(header) {
        await new Promise(resolve => setTimeout(resolve, 25));
        return key;
      };

      const p = await jwt.verify(token, keyFunc, options);
      expect(p).toEqual(payload);
    });

    it('delayed error', async () => {
      const keyFunc = async function(header) {
        await new Promise(resolve => setTimeout(resolve, 25));
        throw new Error('key not found');
      };

      await expect(jwt.verify(token, keyFunc, options)).rejects.toThrow('key not found');
    });
  });

  describe('expiration', () => {
    // { foo: 'bar', iat: 1437018582, exp: 1437018592 }
    const token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE0MzcwMTg1ODIsImV4cCI6MTQzNzAxODU5Mn0.3aR3vocmgRpG05rsI9MpR6z2T_BGtMQaPq2YR6QaroU';
    const key = 'key';

    afterEach(() => {
      try { jest.useRealTimers(); } catch {
        // Ignore errors when restoring clock
      }
    });

    it('should error on expired token', async () => {
      jest.useFakeTimers(); // iat + 58s, exp + 48s
      const options = {algorithms: ['HS256']};

      try {
        await jwt.verify(token, key, options);
        throw new Error('Should have thrown');
      } catch (err) {
        expect(err.name).toBe('TokenExpiredError');
        expect(err.message).toBe('jwt expired');
        expect(err.expiredAt.constructor.name).toBe('Date');
        expect(Number(err.expiredAt)).toBe(1437018592000);
      }
    });

    it('should not error on expired token within clockTolerance interval', (done) => {
      jest.useFakeTimers(); // iat + 12s, exp + 2s
      const options = {algorithms: ['HS256'], clockTolerance: 5 }

      jwt.verify(token, key, options, (err, p) => {
        expect(err).toBeNull();
        expect(p.foo).toBe('bar');
        done();
      });
    });

    describe('option: clockTimestamp', () => {
      const clockTimestamp = 1000000000;
      it('should verify unexpired token relative to user-provided clockTimestamp', (done) => {
        const token = jwt.sign({foo: 'bar', iat: clockTimestamp, exp: clockTimestamp + 1}, key);
        jwt.verify(token, key, {clockTimestamp}, (err) => {
          expect(err).toBeNull();
          done();
        });
      });
      it('should error on expired token relative to user-provided clockTimestamp', (done) => {
        const token = jwt.sign({foo: 'bar', iat: clockTimestamp, exp: clockTimestamp + 1}, key);
        jwt.verify(token, key, {clockTimestamp: clockTimestamp + 1}, (err, p) => {
          expect(err.name).toBe('TokenExpiredError');
          expect(err.message).toBe('jwt expired');
          expect(err.expiredAt.constructor.name).toBe('Date');
          expect(Number(err.expiredAt)).toBe((clockTimestamp + 1) * 1000);
          expect(p).toBeUndefined();
          done();
        });
      });
      it('should verify clockTimestamp is a number', (done) => {
        const token = jwt.sign({foo: 'bar', iat: clockTimestamp, exp: clockTimestamp + 1}, key);
        jwt.verify(token, key, {clockTimestamp: 'notANumber'}, (err, p) => {
          expect(err.name).toBe('JsonWebTokenError');
          expect(err.message).toBe('clockTimestamp must be a number');
          expect(p).toBeUndefined();
          done();
        });
      });
    });

    describe('option: maxAge and clockTimestamp', () => {
      // { foo: 'bar', iat: 1437018582, exp: 1437018800 } exp = iat + 218s
      const token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE0MzcwMTg1ODIsImV4cCI6MTQzNzAxODgwMH0.AVOsNC7TiT-XVSpCpkwB1240izzCIJ33Lp07gjnXVpA';
      it('cannot be more permissive than expiration', (done) => {
        const clockTimestamp = 1437018900;  // iat + 318s (exp: iat + 218s)
        const options = {algorithms: ['HS256'], clockTimestamp, maxAge: '1000y'};

        jwt.verify(token, key, options, (err, p) => {
          // maxAge not exceded, but still expired
          expect(err.name).toBe('TokenExpiredError');
          expect(err.message).toBe('jwt expired');
          expect(err.expiredAt.constructor.name).toBe('Date');
          expect(Number(err.expiredAt)).toBe(1437018800000);
          expect(p).toBeUndefined();
          done();
        });
      });
    });
  });

  describe('when verifying a token with an unsupported public key type', () => {
    it('should throw an error', () => {
      const token = 'eyJhbGciOiJSUzI1NiJ9.eyJpYXQiOjE2Njk5OTAwMDN9.YdjFWJtPg_9nccMnTfQyesWQ0UX-GsWrfCGit_HqjeIkNjoV6dkAJ8AtbnVEhA4oxwqSXx6ilMOfHEjmMlPtyyyVKkWKQHcIWYnqPbNSEv8a7Men8KhJTIWb4sf5YbhgSCpNvU_VIZjLO1Z0PzzgmEikp0vYbxZFAbCAlZCvUlcIc-kdjIRCnDJe0BBrYRxNLEJtYsf7D1yFIFIqw8-VP87yZdExA4eHsTaE84SgnL24ZK5h5UooDx-IRNd_rrMyio8kNy63grVxCWOtkXZ26iZk6v-HMsnBqxvUwR6-8wfaWrcpADkyUO1q3SNsoTdwtflbvfwgjo3uve0IvIzHMw';
      const key = fs.readFileSync(path.join(__dirname, 'dsa-public.pem'));

      expect(() => {
        jwt.verify(token, key);
      }).to.throw('Unknown key type "dsa".');
    });
  });

  describe('when verifying a token with an incorrect public key type', () => {
    it('should throw a validation error if key validation is enabled', () => {
      const token = 'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJwYXkiOiJsb2FkIiwiaWF0IjoxNjcwMjMwNDE2fQ.7TYP8SB_9Tw1fNIfuG60b4tvoLPpDAVBQpV1oepnuKwjUz8GOw4fRLzclo0Q2YAXisJ3zIYMEFsHpYrflfoZJQ';
      const key = fs.readFileSync(path.join(__dirname, 'rsa-public.pem'));

      expect(() => {
        jwt.verify(token, key, { algorithms: ['ES256'] });
      }).to.throw('"alg" parameter for "rsa" key type must be one of: RS256, PS256, RS384, PS384, RS512, PS512.');
    });

    it('should throw an unknown error if key validation is disabled', () => {
      const token = 'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJwYXkiOiJsb2FkIiwiaWF0IjoxNjcwMjMwNDE2fQ.7TYP8SB_9Tw1fNIfuG60b4tvoLPpDAVBQpV1oepnuKwjUz8GOw4fRLzclo0Q2YAXisJ3zIYMEFsHpYrflfoZJQ';
      const key = fs.readFileSync(path.join(__dirname, 'rsa-public.pem'));

      expect(() => {
        jwt.verify(token, key, { algorithms: ['ES256'], allowInvalidAsymmetricKeyTypes: true });
      }).not.throw('"alg" parameter for "rsa" key type must be one of: RS256, PS256, RS384, PS384, RS512, PS512.');
    });
  });
});
