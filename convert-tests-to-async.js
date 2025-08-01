const fs = require('fs');
const path = require('path');
const glob = require('glob');

// Function to convert callback-based tests to async/await
function convertTestFile(filePath) {
  let content = fs.readFileSync(filePath, 'utf8');
  let converted = false;

  // Pattern 1: Simple sign/verify with callback in test
  content = content.replace(
    /it\(([^,]+),\s*\(done\)\s*=>\s*{\s*jwt\.(sign|verify)\(([^}]+?),\s*\(err(?:,\s*(\w+))?\)\s*=>\s*{([^}]+?)done\(\);\s*}\s*\);\s*}\s*\)/g,
    (match, testName, method, args, resultVar, body) => {
      converted = true;
      if (method === 'sign' && resultVar) {
        return `it(${testName}, async () => {\n      const ${resultVar} = await jwt.${method}(${args});\n${body}    });`;
      } else if (method === 'verify' && resultVar) {
        return `it(${testName}, async () => {\n      const ${resultVar} = await jwt.${method}(${args});\n${body}    });`;
      }
      return match;
    }
  );

  // Pattern 2: Error expectation with done callback
  content = content.replace(
    /it\(([^,]+),\s*\(done\)\s*=>\s*{\s*jwt\.(sign|verify)\(([^}]+?),\s*\(err\)\s*=>\s*{\s*expect\(err\)\.to\.be\.ok;\s*done\(\);\s*}\s*\);\s*}\s*\)/g,
    (match, testName, method, args) => {
      converted = true;
      return `it(${testName}, async () => {\n      await expect(jwt.${method}(${args})).rejects.toThrow();\n    });`;
    }
  );

  // Pattern 3: Tests with expect(err) patterns
  content = content.replace(
    /it\(([^,]+),\s*\(done\)\s*=>\s*{([\s\S]*?)}\s*\);/g,
    (match, testName, testBody) => {
      if (testBody.includes('done()') && testBody.includes('jwt.sign') || testBody.includes('jwt.verify')) {
        converted = true;
        let newBody = testBody;

        // Replace done() with nothing
        newBody = newBody.replace(/done\(\);?/g, '');

        // Replace (done) => with async () =>
        const newTest = `it(${testName}, async () => {${newBody}});`;

        // Handle callback patterns
        if (newBody.includes('(err')) {
          // This needs manual review
          console.log(`Manual review needed for test "${testName}" in ${filePath}`);
        }

        return newTest;
      }
      return match;
    }
  );

  // Pattern 4: Replace expect().to patterns with Jest patterns
  content = content.replace(/expect\(([^)]+)\)\.to\.be\.ok/g, 'expect($1).toBeTruthy()');
  content = content.replace(/expect\(([^)]+)\)\.to\.equal\(/g, 'expect($1).toEqual(');
  content = content.replace(/expect\(([^)]+)\)\.to\.have\.length\(/g, 'expect($1).toHaveLength(');
  content = content.replace(/expect\(([^)]+)\)\.not\.have\.property\(/g, 'expect($1).not.toHaveProperty(');
  content = content.replace(/expect\(([^)]+)\)\.to\.be\.instanceof\(/g, 'expect($1).toBeInstanceOf(');

  if (converted) {
    fs.writeFileSync(filePath, content);
    console.log(`Converted: ${filePath}`);
  }

  return converted;
}

// Get all test files
const testFiles = glob.sync('test/**/*.{test,tests}.js', {
  cwd: __dirname,
  absolute: true
});

console.log(`Found ${testFiles.length} test files to convert`);

let convertedCount = 0;
testFiles.forEach(file => {
  if (convertTestFile(file)) {
    convertedCount++;
  }
});

console.log(`\nConverted ${convertedCount} test files`);
console.log('\nNote: Some tests may require manual review, especially those with complex callback patterns.');
console.log('Please run the tests and fix any remaining issues manually.');