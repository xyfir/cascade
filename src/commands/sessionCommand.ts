import type { Command, Argv } from '../types/index.js';
import { getSession } from '../utils/getSession.js';
import { runCommand } from './runCommand.js';
import inquirer from 'inquirer';

/**
 * Create an authenticated interactive session that allows the user to easily
 *  run multiple commands back-to-back.
 */
export async function sessionCommand(argv?: Argv<'session'>): Promise<never> {
  const commands: Command[] = ['save', 'move', 'lock', 'unlock'];

  // Authenticate and prepare session
  const session = await getSession(argv);

  while (true) {
    // Prompt user for the command to run
    const { command } = await inquirer.prompt<{ command: Command }>([
      {
        message: 'command',
        choices: commands,
        name: 'command',
        type: 'list',
      },
    ]);

    // Run command
    await runCommand(command, session).catch(console.error);
  }
}
