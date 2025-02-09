import type { Question } from 'inquirer';
import { getGpwPath } from './getGpwPath.js';
import { GpwPBKDF2 } from './GpwPBKDF2.js';
import inquirer from 'inquirer';

interface PasswordAnswer {
  pass: string;
}

type PasswordPrompt = Question<PasswordAnswer> & {
  type: 'password';
  name: 'pass';
};
import type {
  GpwUnlockedKeychain,
  GpwRepoManifest,
  Session,
  Argv,
} from '../types/index.js';
import fs from 'fs-extra';

/**
 * Generate an authenticated session object by reading the CWD's manifest and
 *  unlocking its keychain.
 */
export async function getSession(argv?: Argv<'session'>): Promise<Session> {
  // Get manifest
  const manifest: GpwRepoManifest = await fs.readJSON(
    getGpwPath('manifest.json'),
  );

  // Get passwords
  const passwords: string[] = [];
  if (argv?.password) {
    if (argv.password.length != manifest.key_stretchers.length) {
      throw Error(
        `Received ${argv.password.length} passwords, expected ${manifest.key_stretchers.length}`,
      );
    }

    passwords.push(...argv.password);
  } else {
    for (let i = 0; i < manifest.key_stretchers.length; i++) {
      await inquirer
        .prompt<PasswordAnswer>([
          {
            message: `Password for key #${i + 1}`,
            type: 'password',
            name: 'pass',
          } as PasswordPrompt,
        ])
        .then((answers) => passwords.push(answers.pass));
    }
  }

  // Derive keys from passwords
  const passkeys = await Promise.all(
    manifest.key_stretchers.map((stretcher, i) =>
      GpwPBKDF2.deriveKey(passwords[i], stretcher.salt, stretcher.iterations),
    ),
  );

  // Create unlocked keychain
  const keychain = JSON.parse(
    JSON.stringify(manifest.locked_keychains[0]),
  ) as GpwUnlockedKeychain;
  for (let i = 0; i < keychain.keys.length; i++) {
    keychain.keys[i].data = passkeys[i];
  }

  return {
    ...manifest,
    unlocked_keychain: keychain,
  };
}
