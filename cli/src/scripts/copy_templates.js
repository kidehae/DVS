import { mkdirSync, readdirSync, copyFileSync, existsSync } from 'fs';
import { join } from 'path';
import { fileURLToPath } from 'url';
import { dirname } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

function copyDir(src, dest) {
  if (!existsSync(src)) {
    console.error(`Source directory does not exist: ${src}`);
    process.exit(1);
  }

  mkdirSync(dest, { recursive: true });
  
  for (const file of readdirSync(src)) {
    const srcPath = join(src, file);
    const destPath = join(dest, file);
    copyFileSync(srcPath, destPath);
  }
}

const projectRoot = join(__dirname, '../..');
copyDir(
  join(projectRoot, 'src/templates'),
  join(projectRoot, 'dist/templates')
);