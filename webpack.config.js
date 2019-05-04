const path = require('path')

module.exports = {
  mode: 'production',
  entry: './webfile.js',
  output: {
    path: path.resolve(__dirname, 'dist'),
    filename: 'jsonwebtoken.min.js'
  }
}
