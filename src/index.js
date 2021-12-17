'use strict';
Object.defineProperty(exports, '__esModule', { value: true });
exports.verify = exports.signAsync = exports.sign = exports.magicHash = void 0;
var bitcoin_message_1 = require('./bitcoin-message');
Object.defineProperty(exports, 'magicHash', {
  enumerable: true,
  get: function () {
    return bitcoin_message_1.magicHash;
  },
});
Object.defineProperty(exports, 'sign', {
  enumerable: true,
  get: function () {
    return bitcoin_message_1.sign;
  },
});
Object.defineProperty(exports, 'signAsync', {
  enumerable: true,
  get: function () {
    return bitcoin_message_1.signAsync;
  },
});
Object.defineProperty(exports, 'verify', {
  enumerable: true,
  get: function () {
    return bitcoin_message_1.verify;
  },
});
