'use strict';

function base64UrlEncode(str) {
  return Buffer.from(str).toString('base64')
    .replace(/\=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
  ;
}

module.exports = {
  base64UrlEncode,
};
