import semver from 'semver';

export const RSA_PSS_KEY_DETAILS_SUPPORTED = semver.satisfies(process.version, '>=16.9.0');