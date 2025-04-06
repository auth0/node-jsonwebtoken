/** @type{import('jest').Config} */
const config = {
  transform: {
    '^.+\\.(t|j)sx?$': '@swc/jest'
  }
}

export default config
