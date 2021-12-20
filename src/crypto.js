'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
exports.hash160 = exports.hash256 = exports.sha256 = void 0;
const createHash = require('create-hash');
function sha256(buffer) {
  return createHash('sha256').update(buffer).digest();
}
exports.sha256 = sha256;
function hash256(buffer) {
  return sha256(sha256(buffer));
}
exports.hash256 = hash256;
function hash160(buffer) {
  return createHash('ripemd160').update(sha256(buffer)).digest();
}
exports.hash160 = hash160;
