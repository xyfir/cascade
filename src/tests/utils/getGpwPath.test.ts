import { getGpwPath } from '../../utils/getGpwPath.js';
import { test } from 'node:test';
import assert from 'node:assert/strict';

test("getGpwPath('')", () => {
  assert.equal(getGpwPath(''), `${process.cwd()}/.gitpw`);
});

test("getGpwPath('files/id.json')", () => {
  assert.equal(
    getGpwPath('files/id.json'),
    `${process.cwd()}/.gitpw/files/id.json`,
  );
});
