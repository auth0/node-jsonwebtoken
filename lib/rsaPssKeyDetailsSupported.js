const [major, minor] = process.version.slice(1).split('.').map(parseInt)

// >=16.9.0
module.exports = major > 16 || (major === 16 && minor >= 9);
