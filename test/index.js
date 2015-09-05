/* global describe, it */

var assert = require('assert')
var PROJECTNAME = require('../')
var fixtures = require('./fixtures')

describe('PROJECTNAME', function () {
  fixtures.forEach(function (f) {
    it('returns ' + f.expected + ' for ' + f.arguments, function () {
      var actual = PROJECTNAME.apply(null, f.arguments)

      assert.strictEqual(actual, f.expected)
    })
  })
})
