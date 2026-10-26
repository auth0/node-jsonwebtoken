const JsonWebTokenError = require('./JsonWebTokenError');

function isBoolean(value) {
  return typeof value === 'boolean';
}

// Ordered: the first failing rule determines the reported error.
const OPTION_RULES = [
  {
    name: 'clockTimestamp',
    // Falsy values are accepted and fall back to the current time.
    isValid: (value) => typeof value === 'number' || !value,
    message: 'clockTimestamp must be a number'
  },
  { name: 'clockTolerance', isValid: Number.isFinite, message: 'clockTolerance must be a finite number' },
  { name: 'ignoreExpiration', isValid: isBoolean, message: 'ignoreExpiration must be a boolean' },
  { name: 'ignoreNotBefore', isValid: isBoolean, message: 'ignoreNotBefore must be a boolean' },
  {
    name: 'nonce',
    isValid: (value) => typeof value === 'string' && value.trim() !== '',
    message: 'nonce must be a non-empty string'
  },
  {
    name: 'allowInvalidAsymmetricKeyTypes',
    isValid: isBoolean,
    message: 'allowInvalidAsymmetricKeyTypes must be a boolean'
  }
];

const ALLOWED_OPTIONS = [
  'algorithms', 'audience', 'issuer', 'subject', 'jwtid', 'complete', 'maxAge'
].concat(OPTION_RULES.map((rule) => rule.name));

module.exports = function validateVerifyOptions(options) {
  const unknownOption = Object.keys(options).find((key) => ALLOWED_OPTIONS.indexOf(key) === -1);
  if (unknownOption !== undefined) {
    return new JsonWebTokenError('"' + unknownOption + '" is not an allowed option');
  }

  const failedRule = OPTION_RULES.find((rule) => options[rule.name] !== undefined && !rule.isValid(options[rule.name]));
  return failedRule ? new JsonWebTokenError(failedRule.message) : null;
};
