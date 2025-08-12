#!/usr/bin/env node
import { program } from "commander";
import chalk from "chalk";
import { scanCommand } from "./commands/scan.js";
// Set up your program
program
    .name('dvs')
    .description(chalk.blue('A sample CLI tool with colorful output'))
    .version('1.0.0');
program.addCommand(scanCommand);
// Add another command with colored output
program
    .command('info')
    .description('Display some information')
    .action(() => {
    console.log(chalk.yellow('=== System Information ==='));
    console.log(chalk.cyan(`Node version: ${process.version}`));
    console.log(chalk.cyan(`Platform: ${process.platform}`));
    console.log(chalk.magenta('Thanks for using this CLI!'));
});
// Add an error example
program
    .command('error')
    .description('Demonstrate error output')
    .action(() => {
    console.error(chalk.red.bold('This is an error message!'));
});
// Parse the command line arguments
program.parse(process.argv);
//# sourceMappingURL=index.js.map