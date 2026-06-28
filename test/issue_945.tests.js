const jwt = require("..");

const KEY = "any_key";

describe("issue 945 - validator.isValid is not a function", () => {
  it("should work", () => {
    jwt.sign({ hasOwnProperty: null }, KEY);
    jwt.sign({ valueOf: null }, KEY);
    jwt.sign({ toString: null }, KEY);
    jwt.sign({ __proto__: null }, KEY);
  });
});
