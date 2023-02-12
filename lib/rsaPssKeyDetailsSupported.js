const [major, minor] = process.version.slice(1).split('.').map(function (v) { return parseInt(v, 10) })

// >=16.9.0
module.exports = major > 16 || (major === 16 && minor >= 9);
