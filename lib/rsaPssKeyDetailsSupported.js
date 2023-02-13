const [major, minor] = process.versions.node.split('.').map((v) => parseInt(v, 10))

// >=16.9.0
module.exports = major > 16 || (major === 16 && minor >= 9);
