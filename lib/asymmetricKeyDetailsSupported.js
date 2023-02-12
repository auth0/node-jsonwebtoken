const [major, minor] = process.version.slice(1).split('.').map(function (v) { return parseInt(v, 10) })

// >=15.7.0
module.exports = major > 15 || (major === 15 && minor >= 7)
