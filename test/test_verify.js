const jwt = require("jsonwebtoken");
const chai = require("chai");

const expect = chai.expect;

const PAYLOAD = "myToken";
const SECRETKEY = "secretKey";
const PAYLOADOBJ = {
  token: "myToken",
};
describe("Array", function () {
  it("1T-2-3T-4", function (done) {
    const token = jwt.sign(PAYLOAD, SECRETKEY);
    const decodedToken = jwt.verify(
      token,
      SECRETKEY,
      {
        clockTimestamp: "aaa",
      },
      (err, decoded) => {
        if (err) {
          console.log("FAIL");
          expect(err.message).to.equal("clockTimestamp must be a number");
          done();
        } else {
          console.log("SUCCESS");
          expect(decoded).to.equal(PAYLOAD);
          done();
        }
      }
    );
  });

  it("1T-2-3F-5T-6", function (done) {
    const token = jwt.sign(PAYLOAD, SECRETKEY);
    const decodedToken = jwt.verify(
      token,
      SECRETKEY,
      {
        clockTimestamp: 2000,
        nonce: null,
      },
      (err, decoded) => {
        if (err) {
          console.log("FAIL");
          expect(err.message).to.equal("nonce must be a non-empty string");
          done();
        } else {
          console.log("SUCCESS");
          expect(decoded).to.equal(PAYLOAD);
          done();
        }
      }
    );
  });

  it("1F-3F-5F-7T-8", function (done) {
    const token = jwt.sign(PAYLOAD, SECRETKEY);
    const decodedToken = jwt.verify(
      null,
      SECRETKEY,
      {
        clockTimestamp: 2000,
      },
      (err, decoded) => {
        if (err) {
          console.log("FAIL");
          expect(err.message).to.equal("jwt must be provided");
          done();
        } else {
          console.log("SUCCESS");
          expect(decoded).to.equal(PAYLOAD);
          done();
        }
      }
    );
  });

  it("1T-2-3F-5F-7F-9T-10", function (done) {
    const token = jwt.sign(PAYLOAD, SECRETKEY);
    const decodedToken = jwt.verify(
      {
        name: "test",
      },
      SECRETKEY,
      {
        clockTimestamp: 2000,
      },
      (err, decoded) => {
        if (err) {
          console.log("FAIL");
          expect(err.message).to.equal("jwt must be a string");
          done();
        } else {
          console.log("SUCCESS");
          expect(decoded).to.equal(PAYLOAD);
          done();
        }
      }
    );
  });

  it("1F-3F-5F-7F-9F-11-12T-13", function (done) {
    const token = jwt.sign(PAYLOAD, SECRETKEY);
    const decodedToken = jwt.verify(
      "invalidToken",
      SECRETKEY,
      {
        clockTimestamp: 2000,
      },
      (err, decoded) => {
        if (err) {
          console.log("FAIL");
          expect(err.message).to.equal("jwt malformed");
          done();
        } else {
          console.log("SUCCESS");
          expect(decoded).to.equal(PAYLOAD);
          done();
        }
      }
    );
  });

  it("1F-3F-5F-7F-9F-11-12F-14-15T-16", function (done) {
    const token = jwt.sign(PAYLOAD, SECRETKEY);
    const decodedToken = jwt.verify(
      token,
      "invalidSecretkey",
      {
        clockTimestamp: 2000,
      },
      (err, decoded) => {
        if (err) {
          console.log("FAIL");
          expect(err.message).to.equal("invalid signature");
          done();
        } else {
          console.log("SUCCESS");
          expect(decoded).to.equal(PAYLOAD);
          done();
        }
      }
    );
  });

  it("1F-3F-5F-7F-9F-11-12F-14-15F-17-18T-19", function (done) {
    const token = jwt.sign(PAYLOADOBJ, SECRETKEY, {
      expiresIn: "100ms",
    });

    // expect("HAHA").to.equal("HAHA");
    // done();

    setTimeout(() => {
      const decodedToken = jwt.verify(
        token,
        SECRETKEY,
        {
          clockTimestamp: Date.now(),
          clockTolerance: -1000,
        },
        (err, decoded) => {
          if (err) {
            console.log("FAIL");
            expect(err.message).to.equal("jwt expired");
            done();
          } else {
            console.log("SUCCESS");
            expect(decoded.token).to.equal(PAYLOADOBJ.token);
            done();
          }
        }
      );
    }, 1500);
  });

  it("1F-3F-5F-7F-9F-11-12F-14-15F-17-18F-20", function (done) {
    const token = jwt.sign(PAYLOADOBJ, SECRETKEY, {
      expiresIn: "100ms",
    });

    // expect("HAHA").to.equal("HAHA");
    // done();

    setTimeout(() => {
      const decodedToken = jwt.verify(
        token,
        SECRETKEY,
        {
          clockTimestamp: 1000,
        },
        (err, decoded) => {
          if (err) {
            console.log("FAIL");
            expect(err.message).to.equal("jwt expired");
            done();
          } else {
            console.log("SUCCESS");
            expect(decoded.token).to.equal(PAYLOADOBJ.token);
            done();
          }
        }
      );
    }, 1500);
  });
});
