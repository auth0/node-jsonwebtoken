# Installation & Setup

This guide covers installing and setting up the `jsonwebtoken` library in your Node.js project.

## Requirements

Before installing, ensure your environment meets these requirements:

- **Node.js** >= 20.0.0
- **npm** >= 10.0.0

You can check your versions:
```bash
node --version  # Should output v20.0.0 or higher
npm --version   # Should output 10.0.0 or higher
```

## Installation

### npm
```bash
npm install jsonwebtoken
```

### yarn
```bash
yarn add jsonwebtoken
```

### pnpm
```bash
pnpm add jsonwebtoken
```

## Basic Setup

### JavaScript (CommonJS)
```javascript
const jwt = require('jsonwebtoken');

// Your secret key - keep this secure!
const secret = 'your-secret-key';

// Basic usage
async function example() {
  const token = await jwt.sign({ userId: 123 }, secret);
  const decoded = await jwt.verify(token, secret);
  console.log(decoded);
}
```

### JavaScript (ES Modules)
```javascript
import jwt from 'jsonwebtoken';

const secret = 'your-secret-key';

// Basic usage
const token = await jwt.sign({ userId: 123 }, secret);
const decoded = await jwt.verify(token, secret);
```

### TypeScript
```typescript
import jwt, { JwtPayload, SignOptions, VerifyOptions } from 'jsonwebtoken';

// Define your payload interface
interface TokenPayload extends JwtPayload {
  userId: number;
  email: string;
}

const secret = 'your-secret-key';

// Type-safe signing
const payload: TokenPayload = {
  userId: 123,
  email: 'user@example.com'
};

const signOptions: SignOptions = {
  expiresIn: '1h',
  algorithm: 'HS256'
};

const token = await jwt.sign(payload, secret, signOptions);

// Type-safe verification
const decoded = await jwt.verify(token, secret) as TokenPayload;
console.log(decoded.userId); // TypeScript knows this is a number
```

## TypeScript Configuration

For TypeScript projects, ensure your `tsconfig.json` includes:

```json
{
  "compilerOptions": {
    "target": "ES2020",
    "module": "commonjs",
    "lib": ["ES2020"],
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "strict": true
  }
}
```

## Environment Variables

For production applications, store secrets in environment variables:

```javascript
// .env file
JWT_SECRET=your-very-secure-secret-key

// app.js
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';

dotenv.config();

const secret = process.env.JWT_SECRET;

if (!secret) {
  throw new Error('JWT_SECRET environment variable is not set');
}

// Use the secret for signing/verifying
const token = await jwt.sign({ userId: 123 }, secret);
```

## Next Steps

Now that you have the library installed and configured:

1. Learn about [creating tokens with jwt.sign()](API-Reference-sign)
2. Understand [verifying tokens with jwt.verify()](API-Reference-verify)
3. Explore [usage examples](Usage-Examples)
4. Review [security best practices](Security-&-Algorithms#best-practices)

## Troubleshooting

### Module Resolution Issues

If you encounter module resolution issues with TypeScript:

```json
// tsconfig.json
{
  "compilerOptions": {
    "moduleResolution": "node",
    "allowSyntheticDefaultImports": true
  }
}
```

### Node.js Version Errors

If you see errors about unsupported Node.js version:
1. Update Node.js to version 20 or higher
2. Use a Node version manager like [nvm](https://github.com/nvm-sh/nvm) to manage multiple versions

### TypeScript Type Errors

Ensure you have the latest version of the library:
```bash
npm update jsonwebtoken
```