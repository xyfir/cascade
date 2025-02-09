import { getUnlockedFileMap } from '../utils/getUnlockedFileMap.js';
import { initCommand } from '../commands/initCommand.js';
import { runCommand } from '../commands/runCommand.js';
import { getSession } from '../utils/getSession.js';
import { getPath } from '../utils/getPath.js';
import { resolve } from 'path';
import { crypto } from '../utils/crypto.js';
import { tmpdir } from 'os';
import assert from 'node:assert/strict';
import test from 'node:test';
import fs from 'fs-extra';

/**
 * @todo test file timestamps plaintext->encrypted
 * @todo test file timestamps encrypted->plaintext
 * @todo test deleting tracked file
 */
test(
  'should handle full encryption workflow',
  { timeout: 20000 },
  async (t) => {
    try {
      // Create temp dir and hijack process.cwd()
      const uuid = crypto.randomUUID();
      const tempDir = resolve(tmpdir(), uuid);
      process.cwd = () => tempDir;
      await fs.mkdir(tempDir);

      // Register cleanup
      t.after(async () => {
        await fs.remove(tempDir);
      });
      const password = ['hunter42', 'hunter24', 'pass123', 'pass456'];

      // Initialize repo
      await initCommand({
        encryption: [
          'AES-256-GCM',
          'XChaCha20-Poly1305',
          'AES-256-GCM',
          'XChaCha20-Poly1305',
        ],
        password,
        vscode: true,
      });

      // Write plaintext files
      await fs.writeFile(getPath('test.txt'), 'Hello World');
      await fs.mkdir(getPath('dir'));
      await fs.writeFile(getPath('dir/abc.md'), 'foo bar');

      // Save files
      await runCommand('save', undefined, { password });

      // Confirm that the plaintext files still exist
      let entries = await fs.readdir(getPath(''));
      assert(entries.includes('test.txt'), 'test.txt should exist');
      assert(entries.includes('dir'), 'dir should exist');

      // Confirm that file map was created and has both entries
      const session = await getSession({ password });
      let maps = await getUnlockedFileMap(session.unlocked_keychain);
      assert.equal(
        Object.keys(maps.locked).length,
        2,
        'should have 2 locked files',
      );
      assert.equal(
        Object.keys(maps.unlocked).length,
        2,
        'should have 2 unlocked files',
      );
      assert(
        Object.values(maps.unlocked).some((v) => v == '/test.txt'),
        'test.txt should be in unlocked map',
      );
      assert(
        Object.values(maps.unlocked).some((v) => v == '/dir/abc.md'),
        'abc.md should be in unlocked map',
      );

      // Lock files
      await runCommand('lock', undefined, { password });

      // Confirm that the plaintext files no longer exist
      entries = await fs.readdir(getPath(''));
      assert(!entries.includes('test.txt'), 'test.txt should not exist');
      assert(!entries.includes('dir'), 'dir should not exist');

      // Unlock files
      await runCommand('unlock', undefined, { password });

      // Confirm plaintext files exist again with original content
      let content = await fs.readFile(getPath('test.txt'), 'utf8');
      assert.equal(content, 'Hello World', 'test.txt content should match');
      content = await fs.readFile(getPath('dir/abc.md'), 'utf8');
      assert.equal(content, 'foo bar', 'abc.md content should match');

      // Move file
      await runCommand('move', undefined, {
        password,
        source: 'test.txt',
        target: '/dir/test2.txt',
      });

      // Confirm that the plaintext file has been moved
      entries = await fs.readdir(getPath(''));
      assert(
        !entries.includes('test.txt'),
        'test.txt should not exist in root',
      );
      entries = await fs.readdir(getPath('dir'));
      assert(entries.includes('test2.txt'), 'test2.txt should exist in dir');

      // Confirm that filemap has been updated
      maps = await getUnlockedFileMap(session.unlocked_keychain);
      assert(
        Object.values(maps.unlocked).some((v) => v == '/dir/test2.txt'),
        'test2.txt should be in unlocked map',
      );
    } catch (error) {
      console.error('Test failed with error:', error);
      throw error;
    }
  },
);
