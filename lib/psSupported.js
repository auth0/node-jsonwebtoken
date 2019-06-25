var crypto = require('crypto');

module.exports = 'constants' in crypto && 'RSA_PKCS1_PSS_PADDING' in crypto.constants && 'RSA_PSS_SALTLEN_DIGEST' in crypto.constants;
