import { Buffer } from 'buffer';

// ECDSA signature format conversion between DER and Jose formats
// Based on ecdsa-sig-formatter package

const MAX_OCTET = 0x80;
const CLASS_UNIVERSAL = 0;
const PRIMITIVE_BIT = 0x20;
const TAG_SEQ = 0x10;
const TAG_INT = 0x02;
const ENCODED_TAG_SEQ = TAG_SEQ | PRIMITIVE_BIT | (CLASS_UNIVERSAL << 6);
const ENCODED_TAG_INT = TAG_INT | (CLASS_UNIVERSAL << 6);

function getSignatureBytes(algorithm: string): number {
  const match = algorithm.match(/ES(\d+)K?$/);
  if (!match) {
    throw new Error('Invalid algorithm');
  }
  
  const bits = parseInt(match[1], 10);
  switch (bits) {
    case 256: return 64;
    case 384: return 96;
    case 512: return 132;
    default: throw new Error(`Unknown algorithm: ${algorithm}`);
  }
}

function concat(...buffers: Buffer[]): Buffer {
  return Buffer.concat(buffers);
}

function countPadding(buf: Buffer, start: number, stop: number): number {
  let padding = 0;
  for (let i = start; i < stop; i++) {
    if (buf[i] === 0x00) {
      padding++;
    } else {
      break;
    }
  }
  return padding;
}

function joseToDer(signature: string, algorithm: string): Buffer {
  const sigBytes = getSignatureBytes(algorithm);
  const sig = Buffer.from(signature, 'base64');
  
  if (sig.length !== sigBytes) {
    throw new Error(`Invalid signature length: ${sig.length}`);
  }
  
  const rBytes = sigBytes / 2;
  const r = sig.slice(0, rBytes);
  const s = sig.slice(rBytes);
  
  const rPadding = countPadding(r, 0, rBytes);
  const sPadding = countPadding(s, 0, rBytes);
  
  const rLength = rBytes - rPadding;
  const sLength = rBytes - sPadding;
  
  const rOffset = rPadding;
  const sOffset = rPadding + rLength + 2 + sPadding + 2;
  
  const length = rLength + sLength + 4;
  
  const der = Buffer.allocUnsafe(length + 2);
  der[0] = ENCODED_TAG_SEQ;
  der[1] = length;
  der[2] = ENCODED_TAG_INT;
  der[3] = rLength;
  
  if (rPadding < 0) {
    der[3] += 1;
    der[4] = 0x00;
    r.copy(der, 5, Math.max(-rPadding, 0));
  } else {
    r.copy(der, 4, rPadding);
  }
  
  der[rLength + 4] = ENCODED_TAG_INT;
  der[rLength + 5] = sLength;
  
  if (sPadding < 0) {
    der[rLength + 5] += 1;
    der[rLength + 6] = 0x00;
    s.copy(der, rLength + 7, Math.max(-sPadding, 0));
  } else {
    s.copy(der, rLength + 6, sPadding);
  }
  
  return der;
}

function derToJose(signature: Buffer, algorithm: string): string {
  const sigBytes = getSignatureBytes(algorithm);
  const rBytes = sigBytes / 2;
  
  let offset = 0;
  if (signature[offset++] !== ENCODED_TAG_SEQ) {
    throw new Error('Invalid DER signature');
  }
  
  let seqLength = signature[offset++];
  if (seqLength === (MAX_OCTET | 1)) {
    seqLength = signature[offset++];
  }
  
  if (signature[offset++] !== ENCODED_TAG_INT) {
    throw new Error('Invalid DER signature');
  }
  
  let rLength = signature[offset++];
  let rOffset = offset;
  offset += rLength;
  
  if (signature[offset++] !== ENCODED_TAG_INT) {
    throw new Error('Invalid DER signature');
  }
  
  let sLength = signature[offset++];
  let sOffset = offset;
  
  const r = Buffer.allocUnsafe(rBytes);
  const s = Buffer.allocUnsafe(rBytes);
  
  // Handle padding for r
  if (rLength > rBytes) {
    rOffset += rLength - rBytes;
    rLength = rBytes;
  }
  r.fill(0);
  signature.copy(r, rBytes - rLength, rOffset, rOffset + rLength);
  
  // Handle padding for s
  if (sLength > rBytes) {
    sOffset += sLength - rBytes;
    sLength = rBytes;
  }
  s.fill(0);
  signature.copy(s, rBytes - sLength, sOffset, sOffset + sLength);
  
  return concat(r, s).toString('base64');
}

export { derToJose, joseToDer };