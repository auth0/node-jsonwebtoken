import semver from 'semver';

export const ASYMMETRIC_KEY_DETAILS_SUPPORTED = semver.satisfies(process.version, '>=15.7.0');