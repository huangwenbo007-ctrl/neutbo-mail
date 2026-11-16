// Rehearsal only: accepts a sqlite_master schema-only JSON snapshot. All data
// inserted below is synthetic; this script never connects to a remote database.
const { DatabaseSync } = require('node:sqlite');
const { readFileSync, copyFileSync, mkdtempSync, unlinkSync, rmdirSync, existsSync } = require('node:fs');
const { join } = require('node:path');
const { tmpdir } = require('node:os');
const assert = require('node:assert/strict');

const schemaPath = process.argv[2];
if (!schemaPath) throw new Error('Provide the schema-only JSON snapshot path');
const schema = JSON.parse(readFileSync(schemaPath, 'utf8'));
const migration = readFileSync(join(__dirname, '../migrations/account-deletion-draft.sql'), 'utf8');
const directory = mkdtempSync(join(tmpdir(), 'neutbo-migration-rehearsal-'));
const file = join(directory, 'test.sqlite');
const backup = join(directory, 'before.sqlite');
let db;
try {
  db = new DatabaseSync(file);
  for (const item of schema) db.exec(item.sql);
  db.exec(`INSERT INTO user(user_id,email,password,salt) VALUES(101,'rehearsal@example.test','synthetic','synthetic');
    INSERT INTO account(account_id,user_id,email) VALUES(102,101,'rehearsal@example.test');
    INSERT INTO email(email_id,user_id,account_id,subject,content) VALUES(103,101,102,'rehearsal','synthetic content');
    INSERT INTO attachments(att_id,user_id,account_id,email_id,key) VALUES(104,101,102,103,'attachments/synthetic');`);
  const snapshot = () => ['user','account','email','attachments'].map(t => db.prepare(`SELECT * FROM ${t}`).all());
  const before = snapshot();
  db.close();
  db = null;
  copyFileSync(file, backup);
  db = new DatabaseSync(file);
  db.exec(migration);
  db.exec(migration);
  assert.deepEqual(snapshot(), before);
  assert.equal(db.prepare('PRAGMA integrity_check').get().integrity_check, 'ok');
  assert.equal(db.prepare("SELECT count(*) AS n FROM sqlite_master WHERE type='table' AND name='account_session_generation'").get().n, 1);
  db.close();
  db = null;
  copyFileSync(backup, file);
  db = new DatabaseSync(file);
  assert.deepEqual(snapshot(), before);
  assert.equal(db.prepare("SELECT count(*) AS n FROM sqlite_master WHERE type='table' AND name='account_session_generation'").get().n, 0);
  assert.equal(db.prepare('PRAGMA integrity_check').get().integrity_check, 'ok');
  db.close();
  db = null;
  console.log('PASS: synthetic mail, two migrations, local backup restore, integrity checks');
} finally {
  if (db) db.close();
  for (const path of [file, backup]) if (existsSync(path)) unlinkSync(path);
  rmdirSync(directory);
}
