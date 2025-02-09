import type { Command, Argv } from '../types/index.js';
import type { Question } from 'inquirer';
import { getSession } from '../utils/getSession.js';
import { runCommand } from './runCommand.js';
import inquirer from 'inquirer';

interface CommandAnswer {
  command: Command;
}

type CommandPrompt = Question<CommandAnswer> & {
  choices: Command[];
  name: 'command';
  type: 'list';
};

/**
 * Create an authenticated interactive session that allows the user to easily
 *  run multiple commands back-to-back.
 */
export async function sessionCommand(argv?: Argv<'session'>): Promise<never> {
  const commands: Command[] = ['save', 'move', 'lock', 'unlock'];

  // Authenticate and prepare session
  const session = await getSession(argv);

  // eslint-disable-next-line no-constant-condition
  while (true) {
    // Prompt user for the command to run
    const { command } = await inquirer.prompt<CommandAnswer>([
      {
        message: 'command',
        choices: commands,
        name: 'command',
        type: 'list',
      } as CommandPrompt,
    ]);

    // Run command
    await runCommand(command, session).catch(console.error);
  }
}
