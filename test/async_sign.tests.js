const jwt = require('../index');
const jws = require('jws');
const PS_SUPPORTED = require('../lib/psSupported');
const {generateKeyPairSync} = require("crypto");

describe('signing a token asynchronously', () => {

  describe('when signing a token', () => {
    const secret = 'shhhhhh';

    it('should return the same result as singing synchronously', async () => {
      const asyncToken = await jwt.sign({ foo: 'bar' }, secret, { algorithm: 'HS256' });
      const syncToken = await jwt.sign({ foo: 'bar' }, secret, { algorithm: 'HS256' });
      expect(typeof asyncToken).toBe('string');
      expect(asyncToken.split('.')).to.have.length(3);
      expect(asyncToken).toBe(syncToken);
    });

    it('should work with empty options', async () => {
      const token = await jwt.sign({abc: 1}, "secret", {});
      expect(token).toBeDefined();
    });

    it('should work without options object at all', async () => {
      const token = await jwt.sign({abc: 1}, "secret");
      expect(token).toBeDefined();
    });


    it('should return error when secret is not a cert for RS256', async () => {
      //this throw an error because the secret is not a cert and RS256 requires a cert.
      await expect(jwt.sign({ foo: 'bar' }, secret, { algorithm: 'RS256' })).rejects.toThrow();
    });

    it('should not work for RS algorithms when modulus length is less than 2048 when allowInsecureKeySizes is false or not set', async () => {
      const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 1024 });

      await expect(jwt.sign({ foo: 'bar' }, privateKey, { algorithm: 'RS256' })).rejects.toThrow();
    });

    it('should work for RS algorithms when modulus length is less than 2048 when allowInsecureKeySizes is true', async () => {
      const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 1024 });

      const token = await jwt.sign({ foo: 'bar' }, privateKey, { algorithm: 'RS256', allowInsecureKeySizes: true });
      expect(token).toBeDefined();
    });

    if (PS_SUPPORTED) {
      it('should return error when secret is not a cert for PS256', async () => {
        //this throw an error because the secret is not a cert and PS256 requires a cert.
        await expect(jwt.sign({ foo: 'bar' }, secret, { algorithm: 'PS256' })).rejects.toThrow();
      });
    }

    it('should return error on wrong arguments', async () => {
      //this throw an error because the secret is not a cert and RS256 requires a cert.
      await expect(jwt.sign({ foo: 'bar' }, secret, { notBefore: {} })).rejects.toThrow();
    });

    it('should return error on wrong arguments (2)', async () => {
      await expect(jwt.sign('string', 'secret', {noTimestamp: true})).rejects.toThrow(Error);
    });

    it('should not stringify the payload', async () => {
      const token = await jwt.sign('string', 'secret', {});
      expect(jws.decode(token).payload).to.equal('string');
    });

    describe('when mutatePayload is not set', () => {
      it('should not apply claims to the original payload object (mutatePayload defaults to false)', async () => {
        const originalPayload = { foo: 'bar' };
        await jwt.sign(originalPayload, 'secret', { notBefore: 60, expiresIn: 600 });
        expect(originalPayload).not.have.property('nbf');
        expect(originalPayload).not.have.property('exp');
      });
    });

    describe('when mutatePayload is set to true', () => {
      it('should apply claims directly to the original payload object', async () => {
        const originalPayload = { foo: 'bar' };
        await jwt.sign(originalPayload, 'secret', { notBefore: 60, expiresIn: 600, mutatePayload: true });
        expect(originalPayload).toHaveProperty('nbf').that.is.a('number');
        expect(originalPayload).toHaveProperty('exp').that.is.a('number');
      });
    });

    describe('secret must have a value', () =>{
      [undefined, '', 0].forEach((secret) =>{
        it(`should return an error if the secret is falsy: ${  typeof secret === 'string' ? '(empty string)' : secret}`, async () => {
        // This is needed since jws will not answer for falsy secrets
          await expect(jwt.sign('string', secret, {})).rejects.toThrow('secretOrPrivateKey must have a value');
        });
      });
    });
  });
});
