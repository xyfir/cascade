import { getPath } from '../../utils/getPath.js';
import { test } from 'node:test';
import assert from 'node:assert/strict';

test("getPath('')", () => {
  assert.equal(getPath(''), process.cwd());
});

test("getPath('.gitpw')", () => {
  assert.equal(getPath('.gitpw'), `${process.cwd()}/.gitpw`);
});
