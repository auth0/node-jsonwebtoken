/* istanbul ignore file */
if (Buffer.isEncoding("base64url")) {
  module.exports = (buf) => buf.toString("base64url");
} else {
  const fromBase64 = (base64) =>
    // eslint-disable-next-line no-div-regex
    base64.replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
  module.exports = (buf) => fromBase64(buf.toString("base64"));
}
