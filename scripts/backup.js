import { chmodSync, mkdirSync, unlinkSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import Database from 'better-sqlite3';

const root = resolve(fileURLToPath(new URL('..', import.meta.url)));
const source = new Database(resolve(root, 'data', 'ayush.sqlite'), { readonly:true, fileMustExist:true });
const backupDirectory = resolve(process.env.BACKUP_DIR || resolve(root, 'backups'));
const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
const destination = resolve(backupDirectory, `ayush-${timestamp}.sqlite`);

try {
  mkdirSync(backupDirectory, { recursive:true, mode:0o700 });
  if (process.platform !== 'win32') chmodSync(backupDirectory, 0o700);
  await source.backup(destination);
  if (process.platform !== 'win32') chmodSync(destination, 0o600);
  console.log(`Encrypted database backup created: ${destination}`);
} catch (error) {
  try { unlinkSync(destination); } catch (cleanupError) {
    if (cleanupError.code !== 'ENOENT') throw cleanupError;
  }
  throw error;
} finally {
  source.close();
}
