const [major, minor] = process.versions.node.split('.').map((v) => parseInt(v, 10))

// ^6.12.0 || >=8.0.0
module.exports = (major === 6 && minor >= 12) || major >= 8
