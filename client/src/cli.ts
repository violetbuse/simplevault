#!/usr/bin/env node
/**
 * CLI for SimpleVault.
 */

import { Command } from 'commander';
import { writeDefaultConfig, DEFAULT_CONFIG_PATH } from './config.js';
import { runDevServerWithWatch } from './server.js';

const program = new Command();

program
  .name('simplevault')
  .description('SimpleVault client and dev server')
  .version('0.1.0');

program
  .command('dev', { isDefault: true })
  .description('Start the dev server')
  .option('-p, --port <number>', 'Port to listen on', '8080')
  .option('-c, --config <path>', 'Path to config JSON file', DEFAULT_CONFIG_PATH)
  .action(async (options) => {
    const port = parseInt(options.port, 10);
    if (isNaN(port)) {
      console.error('Invalid port:', options.port);
      process.exit(1);
    }
    await runDevServerWithWatch({
      configPath: options.config,
      portOverride: port,
    });
  });

program
  .command('init')
  .description('Create a default config file')
  .option('-o, --output <path>', 'Output path', DEFAULT_CONFIG_PATH)
  .action((options) => {
    writeDefaultConfig(options.output);
    console.log(`Created config at ${options.output}`);
  });

program.parse();
