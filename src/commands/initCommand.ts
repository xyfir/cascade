import type { PasswordQuestion, ListQuestion } from 'inquirer';
import { getGpwPath } from '../utils/getGpwPath.js';
import { GpwPBKDF2 } from '../utils/GpwPBKDF2.js';
import { GpwCrypto } from '../utils/GpwCrypto.js';
import { promisify } from 'util';
import { getPath } from '../utils/getPath.js';
import { nanoid } from 'nanoid';
import { exec } from 'child_process';
import inquirer from 'inquirer';
import fs from 'fs-extra';
import type {
  GpwUnlockedKeychain,
  GpwLockedKeychain,
  GpwRepoManifest,
  GpwKeyType,
  GpwKey,
  Argv,
} from '../types/index.js';

const execp = promisify(exec);

/**
 * Initialize a new .gitpw _and_ .git repository within an empty directory.
 */
export async function initCommand(argv: Argv<'init'>): Promise<void> {
  // Check that the directory is empty
  const entries = await fs.readdir(getPath(''));
  if (entries.some((e) => e != '.git')) throw Error('Directory is not empty');

  // Create .gitpw directories
  await fs.mkdir(getGpwPath(''));
  await fs.mkdir(getGpwPath('files'));

  // Run `git init` command
  await execp('git init');

  // Validate arguments
  if (argv?.encryption?.length != argv?.password?.length) {
    throw Error('--encryption,-e and --password,-p count mismatch');
  }
  const useArgv = Array.isArray(argv?.encryption);

  // How many keys should we encrypt the repo with?
  const keyCount = useArgv
    ? argv!.encryption!.length
    : await inquirer
        .prompt<{ keyCount: number }>([
          {
            message: '# of keys to encrypt with',
            default: 1,
            name: 'keyCount',
            type: 'number',
          },
        ])
        .then((a) => a.keyCount);

  // What key types and passwords should we use?
  const encryptWith: [GpwKeyType, string][] = [];
  if (useArgv) {
    for (let i = 0; i < keyCount; i++) {
      encryptWith.push([argv!.encryption![i], argv!.password![i]]);
    }
  } else {
    const questions: (ListQuestion | PasswordQuestion)[] = [];
    for (let i = 0; i < keyCount; i++) {
      questions.push({
        message: `Type of key #${i + 1}`,
        choices: ['XChaCha20-Poly1305', 'AES-256-GCM'] as GpwKeyType[],
        default: (i == 0 ? 'AES-256-GCM' : 'XChaCha20-Poly1305') as GpwKeyType,
        name: `keyType${i}`,
        type: 'list',
      } as ListQuestion);
      questions.push({
        message: `Password for key #${i + 1}`,
        choices: ['XChaCha20-Poly1305', 'AES-256-GCM'] as GpwKeyType[],
        default: (i == 0 ? 'AES-256-GCM' : 'XChaCha20-Poly1305') as GpwKeyType,
        name: `keyPass${i}`,
        type: 'password',
      } as PasswordQuestion);
    }
    const answers = await inquirer.prompt(questions);

    for (let i = 0; i < keyCount; i++) {
      encryptWith.push([
        answers[`keyType${i}`] as GpwKeyType,
        answers[`keyPass${i}`] as string,
      ]);
    }
  }

  // Should we configure the repo for VS Code?
  const vsCode = useArgv
    ? argv!.vscode!
    : await inquirer.prompt<{ vsCode: boolean }>([
        {
          message: 'Configure for VS Code?',
          default: false,
          type: 'confirm',
          name: 'vsCode',
        },
      ]);

  // Create repo manifest
  const manifest: GpwRepoManifest = {
    locked_keychains: [],
    key_stretchers: Array(keyCount)
      .fill(0)
      .map(() => ({
        iterations: GpwPBKDF2.generateIterations(),
        type: 'PBKDF2-SHA-512',
        salt: GpwPBKDF2.generateSalt(),
      })),
    version: 'com.xyfir.gitpw/0.0.0',
  };

  // Derive keys from passwords
  const passkeys = await Promise.all(
    manifest.key_stretchers.map((stretcher, i) =>
      GpwPBKDF2.deriveKey(
        encryptWith[i][1],
        stretcher.salt,
        stretcher.iterations,
      ),
    ),
  );

  // Create un/locked keychains
  const keychain: GpwUnlockedKeychain = {
    keys: Array(keyCount)
      .fill(0)
      .map(
        (_, i): GpwKey => ({
          type: encryptWith[i][0],
          data: passkeys[i],
        }),
      ),
    id: nanoid(),
  };
  const lockedKeychain = JSON.parse(
    JSON.stringify(keychain),
  ) as GpwLockedKeychain;
  for (const key of lockedKeychain.keys) {
    key.data = await GpwCrypto.encrypt(key.data, keychain);
  }
  manifest.locked_keychains.push(lockedKeychain);

  // Write files
  await fs.writeJSON(getGpwPath('manifest.json'), manifest, { spaces: 2 });
  await fs.writeJSON(getGpwPath('map.json'), {}, { spaces: 2 });
  await fs.writeFile(
    getPath('.gitignore'),
    ['/*', '!/.gitignore', vsCode ? '!/.vscode/' : '', '!/.gitpw/']
      .filter(Boolean)
      .join('\n'),
  );

  // Configure for VS Code:
  // - Only search non-config plaintext ignored by git
  if (vsCode) {
    await fs.mkdir(getPath('.vscode'));
    await fs.writeJSON(
      getPath('.vscode/settings.json'),
      {
        'search.useIgnoreFiles': false,
        'search.exclude': {
          '.gitignore': true,
          '.vscode': true,
          '.gitpw': true,
        },
      },
      { spaces: 2 },
    );
  }

  console.log('Initialized gitpw repo');
}
