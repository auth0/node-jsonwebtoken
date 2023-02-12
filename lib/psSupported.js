const [major, minor] = process.version.slice(1).split('.').map(function (v) { return parseInt(v, 10) })

// ^6.12.0 || >=8.0.0
module.exports = (major === 6 && minor >= 12) || major >= 8
