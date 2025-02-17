const jwt = require("../index");
const expect = require("chai").expect;
let jose;

try {
  jose = require("jose");
} catch (_) {}

for (const [alg, opts] of [
  ["HS256"],
  ["RS256"],
  ["PS256"],
  ["ES256"],
  ["ES256K"],
  ["ES384"],
  ["ES512"],
  ["EdDSA", { crv: "Ed25519" }],
  ["EdDSA", { crv: "Ed448" }],
]) {
  const conditionalDescribe =
    parseInt(process.versions.node, 10) >= 18 ? describe : describe.skip;

  conditionalDescribe(
    `${alg} roundtrips${opts ? ` with ${JSON.stringify(opts)}` : ""}`,
    function () {
      if (alg.startsWith("HS")) {
        before(function (done) {
          jose.generateSecret(alg, opts).then((secretKey) => {
            this.publicKey = this.privateKey = secretKey;
            done();
          }, done);
        });
      } else {
        before(function (done) {
          jose.generateKeyPair(alg, opts).then((kp) => {
            this.publicKey = kp.publicKey;
            this.privateKey = kp.privateKey;
            done();
          }, done);
        });
      }

      describe("round trip jsonwebtoken > jsonwebtoken", function () {
        it("without callback", function () {
          expect(() => {
            const token = jwt.sign({}, this.privateKey, { algorithm: alg });
            jwt.verify(token, this.publicKey);
          }).not.to.throw();
        });

        it("with callback", function (done) {
          jwt.sign({}, this.privateKey, { algorithm: alg }, (err, token) => {
            if (err) return done(err);
            jwt.verify(token, this.publicKey, (err) => {
              if (err) return done(err);
              done();
            });
          });
        });
      });

      describe("round trip external > jsonwebtoken", function () {
        before(function (done) {
          new jose.SignJWT()
            .setProtectedHeader({ alg })
            .sign(this.privateKey)
            .then((token) => {
              this.token = token;
              done();
            }, done);
        });

        it("without callback", function () {
          expect(() => {
            jwt.verify(this.token, this.publicKey);
          }).not.to.throw();
        });

        it("with callback", function (done) {
          jwt.verify(this.token, this.publicKey, (err) => {
            if (err) return done(err);
            done();
          });
        });
      });

      describe("round trip jsonwebtoken > external", function () {
        it("without callback", function (done) {
          const token = jwt.sign({}, this.privateKey, { algorithm: alg });
          jose.jwtVerify(token, this.publicKey).then(() => done(), done);
        });

        it("with callback", function (done) {
          jwt.sign({}, this.privateKey, { algorithm: alg }, (err, token) => {
            if (err) return done(err);
            jose.jwtVerify(token, this.publicKey).then(() => done(), done);
          });
        });
      });
    }
  );
}
