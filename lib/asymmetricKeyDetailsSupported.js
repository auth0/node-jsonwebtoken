const [major, minor] = process.versions.node.split('.').map((v) => parseInt(v, 10))

// >=15.7.0
module.exports = major > 15 || (major === 15 && minor >= 7)
