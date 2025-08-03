declare namespace jest {
  interface Matchers<R> {
    toBeValidJWT(): R;
    toHaveJWTStructure(): R;
  }
}

export {};