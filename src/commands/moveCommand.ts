import { getUnlockedFileMap } from '../utils/getUnlockedFileMap.js';
import type { Session, Argv } from '../types/index.js';
import { getGpwPath } from '../utils/getGpwPath.js';
import { GpwCrypto } from '../utils/GpwCrypto.js';
import { getPath } from '../utils/getPath.js';
import inquirer from 'inquirer';
import fs from 'fs-extra';

/**
 * Move a plaintext file and its encrypted file map routing to a new path.
 */
export async function moveCommand(
  argv: Argv<'move'> = {},
  session: Session,
): Promise<void> {
  const rootDir = getPath('');

  // Prompt for source if not supplied
  let source = argv!.source;
  if (!source) {
    source = await inquirer
      .prompt<{ source: string }>([
        {
          message: 'Source file to move',
          name: 'source',
          type: 'input',
        },
      ])
      .then((a) => a.source);
  }

  // Confirm source exists
  const sourcePath = getPath(source!);
  if (!(await fs.pathExists(sourcePath))) throw 'Source file does not exist';
  source = sourcePath.replace(rootDir, '');

  // Get file ID by checking the source path
  const map = await getUnlockedFileMap(session.unlocked_keychain);
  const id = Object.entries(map.unlocked).find((e) => e[1] == source)?.[0];
  if (!id) throw `Source file ${source} not tracked by gitpw`;

  // Prompt for target if not supplied
  let target = argv!.target;
  if (!target) {
    target = await inquirer
      .prompt<{ target: string }>([
        {
          message: 'Target path to move source to',
          name: 'target',
          type: 'input',
        },
      ])
      .then((a) => a.target);
  }

  // Confirm target does not exist
  const targetPath = getPath(target!);
  if (await fs.pathExists(targetPath)) throw 'Target file already exists';
  target = targetPath.replace(rootDir, '');

  // Move file
  await fs.move(sourcePath, targetPath);

  // Update file map
  map.locked[id] = await GpwCrypto.encrypt(target!, session.unlocked_keychain);
  await fs.writeJSON(getGpwPath('map.json'), map.locked, { spaces: 2 });
}
