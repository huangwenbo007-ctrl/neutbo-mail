// Isolated draft-schema checks. No production database is accessed.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { DatabaseSync } = require('node:sqlite');
const { readFileSync } = require('node:fs');
const { join } = require('node:path');

test('migration can be repeated without changing existing mailbox data', () => {
  const db = new DatabaseSync(':memory:');
  db.exec(`CREATE TABLE user (user_id INTEGER PRIMARY KEY, email TEXT NOT NULL);
    CREATE TABLE email (email_id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, subject TEXT);
    CREATE TABLE attachments (att_id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, key TEXT NOT NULL);
    INSERT INTO user VALUES (1, 'existing@example.test');
    INSERT INTO email VALUES (2, 1, 'existing message');
    INSERT INTO attachments VALUES (3, 1, 'attachments/existing');`);
  const migration = readFileSync(join(__dirname, '../migrations/account-deletion-draft.sql'), 'utf8');
  db.exec(migration);
  db.exec(migration);
  assert.equal(db.prepare('SELECT email FROM user WHERE user_id=1').get().email, 'existing@example.test');
  assert.equal(db.prepare('SELECT subject FROM email WHERE email_id=2').get().subject, 'existing message');
  assert.equal(db.prepare('SELECT key FROM attachments WHERE att_id=3').get().key, 'attachments/existing');
  assert.equal(db.prepare("SELECT count(*) AS n FROM sqlite_master WHERE type='table' AND name='account_session_generation'").get().n, 1);
  db.close();
});

test('isolated preview upgrade adds missing recovery columns without inventing proof', () => {
  const db=new DatabaseSync(':memory:');
  db.exec("CREATE TABLE account_recovery_email_code(user_id INTEGER PRIMARY KEY); CREATE TABLE account_recovery_support_ticket(user_id INTEGER PRIMARY KEY, reference_hash TEXT NOT NULL); INSERT INTO account_recovery_email_code VALUES(1); INSERT INTO account_recovery_support_ticket VALUES(1,'old-hash');");
  const reference=readFileSync(join(__dirname,'../migrations/preview-recovery-reference-column.sql'),'utf8');
  const generation=readFileSync(join(__dirname,'../migrations/preview-recovery-ticket-generation.sql'),'utf8');
  db.exec(reference); db.exec(generation);
  assert.equal(db.prepare('SELECT reference_hash FROM account_recovery_email_code WHERE user_id=1').get().reference_hash,'');
  assert.equal(db.prepare('SELECT generation FROM account_recovery_support_ticket WHERE user_id=1').get().generation,0);
  assert.throws(()=>db.exec(reference),/duplicate column/);
  assert.throws(()=>db.exec(generation),/duplicate column/);
  db.close();
});

test('enforces the recovery period and known lifecycle states', () => {
  const db = new DatabaseSync(':memory:');
  db.exec(readFileSync(join(__dirname, '../migrations/account-deletion-draft.sql'), 'utf8'));
  const insert = db.prepare('INSERT INTO account_deletion_request VALUES (?, ?, ?, ?)');
  assert.throws(() => insert.run(1, 100, 100 + 2591999, 'pending'));
  assert.throws(() => insert.run(1, 100, 100 + 2592000, 'invalid'));
  insert.run(1, 100, 100 + 2592000, 'pending');
  assert.throws(() => insert.run(1, 101, 101 + 2592000, 'pending'));
  db.close();
});

test('only one writer or cleaner may reserve a shared object', async () => {
  const { acquireObjectLock, releaseObjectLock } = await import('../src/service/account-deletion-state.js');
  const raw = new DatabaseSync(':memory:');
  raw.exec(readFileSync(join(__dirname, '../migrations/account-deletion-draft.sql'), 'utf8'));
  const db = {prepare(sql) {return {bind(...args) {return {async run() {return {meta:{changes:Number(raw.prepare(sql).run(...args).changes)}};}};}};}};
  const [writer, cleaner] = await Promise.all([
    acquireObjectLock(db, 'KV', 'attachments/shared', 'writer-token', 100),
    acquireObjectLock(db, 'KV', 'attachments/shared', 'cleaner-token', 100),
  ]);
  assert.equal(Number(writer) + Number(cleaner), 1);
  assert.equal(await releaseObjectLock(db, 'KV', 'attachments/shared', 'wrong-token'), false);
  assert.equal(await acquireObjectLock(db, 'KV', 'attachments/shared', 'third-token', 999999999), false);
  assert.equal(await releaseObjectLock(db, 'KV', 'attachments/shared', writer ? 'writer-token' : 'cleaner-token'), true);
  assert.equal(await acquireObjectLock(db, 'KV', 'attachments/shared', 'third-token', 999999999), true);
  raw.close();
});

test('a writer reserves all attachment keys or performs no write', async () => {
  const { acquireObjectLock, releaseObjectLock, withObjectLocks } = await import('../src/service/account-deletion-state.js');
  const raw = new DatabaseSync(':memory:');
  raw.exec(readFileSync(join(__dirname, '../migrations/account-deletion-draft.sql'), 'utf8'));
  const db = {prepare(sql) {return {bind(...args) {return {async run() {return {meta:{changes:Number(raw.prepare(sql).run(...args).changes)}};}};}};}};
  assert.equal(await acquireObjectLock(db, 'R2', 'z-shared', 'cleaner', 10), true);
  let writes = 0;
  await assert.rejects(withObjectLocks(db, 'KV', ['z-shared', 'a-new', 'a-new'], 'writer', 11, async () => {writes++;}), /busy/);
  assert.equal(writes, 0);
  assert.equal(raw.prepare("SELECT count(*) AS n FROM attachment_object_lock WHERE object_key = 'a-new'").get().n, 0);
  assert.equal(await releaseObjectLock(db, 'R2', 'z-shared', 'cleaner'), true);
  await assert.rejects(withObjectLocks(db, 'KV', ['z-shared', 'a-new'], 'writer', 12, async () => {throw new Error('write failure');}), /write failure/);
  assert.equal(raw.prepare('SELECT count(*) AS n FROM attachment_object_lock').get().n, 0);
  assert.equal(await withObjectLocks(db, 'KV', ['z-shared', 'a-new'], 'writer', 13, async () => ++writes), 1);
  assert.equal(raw.prepare('SELECT count(*) AS n FROM attachment_object_lock').get().n, 0);
  raw.close();
});

test('bounded lock retries wait only for acquisition and never repeat a write', async () => {
  const { acquireObjectLock, releaseObjectLock, withObjectLocks } = await import('../src/service/account-deletion-state.js');
  const raw = new DatabaseSync(':memory:');
  raw.exec(readFileSync(join(__dirname, '../migrations/account-deletion-draft.sql'), 'utf8'));
  const db = {prepare(sql) {return {bind(...args) {return {async run() {return {meta:{changes:Number(raw.prepare(sql).run(...args).changes)}};}};}};}};
  assert.equal(await acquireObjectLock(db,'KV','z-shared','holder',10),true);
  let writes=0;
  const waiting=withObjectLocks(db,'KV',['a-first','z-shared'],'writer',11,async()=>++writes,{retries:4,delayMs:30});
  await new Promise(resolve=>setTimeout(resolve,45));
  assert.equal(writes,0);
  assert.equal(await releaseObjectLock(db,'KV','z-shared','holder'),true);
  assert.equal(await waiting,1);
  assert.equal(writes,1);
  assert.equal(raw.prepare('SELECT count(*) AS n FROM attachment_object_lock').get().n,0);
  await assert.rejects(withObjectLocks(db,'KV',['a-first'],'writer',12,async()=>{writes++;throw new Error('Attachment temporarily busy')},{retries:4,delayMs:1}),/busy/);
  assert.equal(writes,2); // A failure after the write started must never be retried.
  assert.equal(await acquireObjectLock(db,'KV','z-shared','holder',13),true);
  await assert.rejects(withObjectLocks(db,'KV',['a-first','z-shared'],'writer',14,async()=>{writes++},{retries:1,delayMs:1}),/busy/);
  assert.equal(writes,2);
  assert.equal(raw.prepare("SELECT count(*) AS n FROM attachment_object_lock WHERE object_key='a-first'").get().n,0);
  assert.equal(await releaseObjectLock(db,'KV','z-shared','holder'),true);
  raw.close();
});

test('keeps shared objects and retries failed unshared object deletion', async () => {
  const { processQueuedObject, acquireObjectLock, releaseObjectLock, recordConfirmedObjectOrigin } = await import('../src/service/account-deletion-state.js');
  const raw = new DatabaseSync(':memory:');
  raw.exec(readFileSync(join(__dirname, '../migrations/account-deletion-draft.sql'), 'utf8'));
  raw.exec(`CREATE TABLE attachments (user_id INTEGER, key TEXT);
    INSERT INTO attachments VALUES (2, 'attachments/shared');
    INSERT INTO attachment_object_origin VALUES ('attachments/shared', 'KV', 'isolated-test-kv', 'known');
    INSERT INTO account_deletion_object_queue VALUES ('KV', 'attachments/shared', 1), ('KV', 'attachments/private', 1);`);
  const db = {prepare(sql) {return {bind(...args) {return {
    async run() {return {meta:{changes:Number(raw.prepare(sql).run(...args).changes)}};},
    async first() {return raw.prepare(sql).get(...args);},
  };}};}};
  const target = {storageType:'KV',storeId:'isolated-test-kv'};
  const shared = {userId:1, storageType:'KV', key:'attachments/shared'};
  let deletes = 0;
  assert.equal(await processQueuedObject(db, shared, 'cleaner-shared', 100, async () => {deletes++;},target), 'shared');
  assert.equal(deletes, 0);
  assert.equal(raw.prepare("SELECT count(*) AS n FROM account_deletion_object_queue WHERE object_key='attachments/shared'").get().n, 1);
  const own = {userId:1, storageType:'KV', key:'attachments/private'};
  assert.equal(await processQueuedObject(db, own, 'cleaner-unknown', 100, async () => {deletes++;},target),'unresolved');
  await assert.rejects(recordConfirmedObjectOrigin(db, own.key, 'KV', target.storeId, 'writer'), /reservation/);
  assert.equal(await acquireObjectLock(db, 'KV', own.key, 'writer', 100), true);
  await recordConfirmedObjectOrigin(db, own.key, 'KV', target.storeId, 'writer');
  assert.equal(await releaseObjectLock(db, 'KV', own.key, 'writer'), true);
  assert.equal(await processQueuedObject(db, own, 'cleaner-wrong', 100, async () => {deletes++;},{storageType:'KV',storeId:'other-kv'}),'unresolved');
  assert.equal(deletes, 0);
  await assert.rejects(processQueuedObject(db, own, 'cleaner-fail', 101, async () => {throw new Error('storage unavailable');},target));
  assert.equal(raw.prepare("SELECT count(*) AS n FROM account_deletion_object_queue WHERE object_key='attachments/private'").get().n, 1);
  let unblock;
  let started;
  const ready = new Promise(resolve => { started = resolve; });
  const wait = new Promise(resolve => { unblock = resolve; });
  const cleanup = processQueuedObject(db, own, 'cleaner-retry', 102, async () => {started(); await wait; deletes++;},target);
  await ready;
  assert.equal(await acquireObjectLock(db, 'KV', 'attachments/private', 'concurrent-writer', 103), false);
  unblock();
  assert.equal(await cleanup, 'deleted');
  assert.equal(deletes, 1);
  assert.equal(raw.prepare("SELECT count(*) AS n FROM account_deletion_object_queue WHERE object_key='attachments/private'").get().n, 0);
  assert.equal(await acquireObjectLock(db,'KV',shared.key,'shared-writer',104),true);
  await recordConfirmedObjectOrigin(db,shared.key,'KV',target.storeId,'shared-writer');
  assert.equal(await releaseObjectLock(db,'KV',shared.key,'shared-writer'),true);
  raw.prepare('DELETE FROM attachments WHERE key=?').run(shared.key);
  assert.equal(await processQueuedObject(db,shared,'cleaner-after-last-ref',105,async()=>{deletes++},target),'deleted');
  assert.equal(deletes,2);
  raw.close();
});

test('marks conflicting attachment storage origins ambiguous and never deletes them', async () => {
  const { recordConfirmedObjectOrigin, processQueuedObject, acquireObjectLock, releaseObjectLock } = await import('../src/service/account-deletion-state.js');
  const raw = new DatabaseSync(':memory:');
  raw.exec(readFileSync(join(__dirname, '../migrations/account-deletion-draft.sql'), 'utf8'));
  raw.exec("CREATE TABLE attachments (user_id INTEGER, key TEXT); INSERT INTO account_deletion_object_queue VALUES ('KV','attachments/collision',1)");
  const db={prepare(sql){return {bind(...args){return {
    async run(){return {meta:{changes:Number(raw.prepare(sql).run(...args).changes)}}},
    async first(){return raw.prepare(sql).get(...args)},
  }}}}};
  const key='attachments/collision';
  assert.equal(await acquireObjectLock(db,'KV',key,'writer',1),true);
  await recordConfirmedObjectOrigin(db,key,'KV','test-store-a','writer');
  await recordConfirmedObjectOrigin(db,key,'KV','test-store-a','writer');
  assert.equal(raw.prepare('SELECT state FROM attachment_object_origin WHERE object_key=?').get(key).state,'known');
  await recordConfirmedObjectOrigin(db,key,'KV','test-store-b','writer');
  await recordConfirmedObjectOrigin(db,key,'KV','test-store-a','writer');
  assert.equal(await releaseObjectLock(db,'KV',key,'writer'),true);
  assert.equal(raw.prepare('SELECT state FROM attachment_object_origin WHERE object_key=?').get(key).state,'ambiguous');
  let deletes=0;
  assert.equal(await processQueuedObject(db,{userId:1,storageType:'KV',key},'cleaner',10,async()=>{deletes++},{storageType:'KV',storeId:'test-store-a'}),'unresolved');
  assert.equal(deletes,0);
  assert.equal(raw.prepare('SELECT count(*) AS n FROM account_deletion_object_queue').get().n,1);
  raw.close();
});

test('stages attachment keys and removes only the claimed user metadata', async () => {
  const { stagePurge } = await import('../src/service/account-deletion-state.js');
  const raw = new DatabaseSync(':memory:');
  raw.exec(readFileSync(join(__dirname, '../migrations/account-deletion-draft.sql'), 'utf8'));
  raw.exec(`CREATE TABLE user (user_id INTEGER PRIMARY KEY, is_del INTEGER NOT NULL DEFAULT 1);
    CREATE TABLE star (user_id INTEGER); CREATE TABLE email (email_id INTEGER PRIMARY KEY, user_id INTEGER);
    CREATE TABLE account (user_id INTEGER); CREATE TABLE oauth (user_id INTEGER, oauth_id INTEGER);
    CREATE TABLE role (role_id INTEGER PRIMARY KEY, user_id INTEGER);
    CREATE TABLE reg_key (rege_key_id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL DEFAULT 0);
    CREATE TABLE attachments (user_id INTEGER, key TEXT);
    INSERT INTO user (user_id) VALUES (1), (2); INSERT INTO attachments VALUES (1, 'shared'), (1, 'unique'), (2, 'shared');
    INSERT INTO email VALUES (11, 1), (22, 2); INSERT INTO account VALUES (1), (2);
    INSERT INTO inbound_attachment_failure VALUES (11, 'partial', 10), (22, 'other-partial', 10);
    INSERT INTO role VALUES (10, 1), (20, 2); INSERT INTO reg_key VALUES (100, 1), (200, 2);
    INSERT INTO account_reauth_rate VALUES (1, 10, 1), (2, 10, 1);
    INSERT INTO google_deletion_challenge VALUES (1, 'one', 'session', 'nonce', 'verifier', 'subject', 100), (2, 'two', 'session', 'nonce', 'verifier', 'subject', 100);
    INSERT INTO account_deletion_request VALUES (1, 0, 2592000, 'pending');`);
  const db = {
    prepare(sql) { return { bind(...args) { return {run() { return {meta:{changes:Number(raw.prepare(sql).run(...args).changes)}}; }}; } }; },
    async batch(statements) { raw.exec('BEGIN'); try { const out = statements.map(s => s.run()); raw.exec('COMMIT'); return out; } catch (e) {raw.exec('ROLLBACK'); throw e;} },
  };
  await stagePurge(db, 1);
  assert.equal(raw.prepare('SELECT count(*) AS n FROM user').get().n, 2);
  raw.exec("UPDATE account_deletion_request SET state = 'purging' WHERE user_id = 1");
  raw.exec('UPDATE user SET is_del = 0 WHERE user_id = 1');
  await stagePurge(db, 1);
  assert.equal(raw.prepare('SELECT count(*) AS n FROM user WHERE user_id=1').get().n, 1);
  assert.equal(raw.prepare('SELECT count(*) AS n FROM account_deletion_object_queue').get().n, 0);
  assert.equal(raw.prepare('SELECT user_id FROM role WHERE role_id=10').get().user_id, 1);
  assert.equal(raw.prepare('SELECT user_id FROM reg_key WHERE rege_key_id=100').get().user_id, 1);
  raw.exec('UPDATE user SET is_del = 1 WHERE user_id = 1');
  raw.exec("CREATE TRIGGER fail_purge BEFORE DELETE ON email BEGIN SELECT RAISE(ABORT, 'simulated failure'); END");
  await assert.rejects(stagePurge(db, 1));
  assert.equal(raw.prepare('SELECT count(*) AS n FROM attachments WHERE user_id=1').get().n, 2);
  assert.equal(raw.prepare('SELECT count(*) AS n FROM account_deletion_object_queue').get().n, 0);
  raw.exec('DROP TRIGGER fail_purge');
  await stagePurge(db, 1);
  await stagePurge(db, 1); // A retry must be harmless.
  assert.equal(raw.prepare('SELECT count(*) AS n FROM user WHERE user_id=1').get().n, 0);
  assert.equal(raw.prepare('SELECT count(*) AS n FROM attachments WHERE user_id=2 AND key=\'shared\'').get().n, 1);
  assert.equal(raw.prepare('SELECT count(*) AS n FROM account_deletion_object_queue WHERE user_id=1').get().n, 3);
  assert.equal(raw.prepare("SELECT count(*) AS n FROM account_deletion_object_queue WHERE user_id=1 AND storage_type='UNRESOLVED'").get().n, 3);
  assert.equal(raw.prepare('SELECT count(*) AS n FROM inbound_attachment_failure WHERE email_id=11').get().n, 0);
  assert.equal(raw.prepare('SELECT count(*) AS n FROM inbound_attachment_failure WHERE email_id=22').get().n, 1);
  assert.equal(raw.prepare('SELECT count(*) AS n FROM email WHERE user_id=2').get().n, 1);
  assert.equal(raw.prepare('SELECT user_id FROM role WHERE role_id=10').get().user_id, null);
  assert.equal(raw.prepare('SELECT user_id FROM role WHERE role_id=20').get().user_id, 2);
  assert.equal(raw.prepare('SELECT user_id FROM reg_key WHERE rege_key_id=100').get().user_id, 0);
  assert.equal(raw.prepare('SELECT user_id FROM reg_key WHERE rege_key_id=200').get().user_id, 2);
  assert.equal(raw.prepare('SELECT count(*) AS n FROM account_reauth_rate WHERE user_id=1').get().n, 0);
  assert.equal(raw.prepare('SELECT count(*) AS n FROM account_reauth_rate WHERE user_id=2').get().n, 1);
  assert.equal(raw.prepare('SELECT count(*) AS n FROM google_deletion_challenge WHERE user_id=1').get().n, 0);
  assert.equal(raw.prepare('SELECT count(*) AS n FROM google_deletion_challenge WHERE user_id=2').get().n, 1);
  raw.close();
});

test('requests, restores and locks an expired request atomically', async () => {
  const { requestDeletion: requestDeletionRaw, restoreDeletion, claimDeletion, readActiveSessionGeneration, withAccountLock } = await import('../src/service/account-deletion-state.js');
  const requestDeletion = (db, userId, now) => requestDeletionRaw(db, userId, now, 'admin@example.com');
  const raw = new DatabaseSync(':memory:');
  raw.exec("CREATE TABLE user (user_id INTEGER PRIMARY KEY, email TEXT NOT NULL DEFAULT 'user@example.com', is_del INTEGER NOT NULL DEFAULT 0, status INTEGER NOT NULL DEFAULT 0); INSERT INTO user (user_id) VALUES (1), (2); INSERT INTO user (user_id, email) VALUES (4, 'Admin@Example.com')");
  raw.exec(readFileSync(join(__dirname, '../migrations/account-deletion-draft.sql'), 'utf8'));
  const db = {
    prepare(sql) {
      return { bind(...args) { return {
        run() { return { meta: { changes: Number(raw.prepare(sql).run(...args).changes) } }; },
        async first() { return raw.prepare(sql).get(...args); },
      }; } };
    },
    async batch(statements) {
      raw.exec('BEGIN');
      try { const out = statements.map(statement => statement.run()); raw.exec('COMMIT'); return out; }
      catch (error) { raw.exec('ROLLBACK'); throw error; }
    },
  };
  const start = Math.floor(Date.now() / 1000);
  const due = start + 30 * 86400;
  await assert.rejects(requestDeletionRaw(db, 1, start), /Administrator identity is required/);
  assert.equal(await requestDeletion(db, 4, start), false);
  assert.equal(raw.prepare('SELECT is_del FROM user WHERE user_id=4').get().is_del, 0);
  assert.equal(raw.prepare('SELECT count(*) AS n FROM account_deletion_request WHERE user_id=4').get().n, 0);
  assert.equal(await readActiveSessionGeneration(db, 1), 0);
  let unlock;
  let started;
  const ready = new Promise(resolve => {started = resolve;});
  const hold = new Promise(resolve => {unlock = resolve;});
  const writer = withAccountLock(db, 1, async () => {started(); await hold;});
  await ready;
  await assert.rejects(requestDeletion(db, 1, start), /busy/);
  assert.equal(raw.prepare('SELECT is_del FROM user WHERE user_id=1').get().is_del, 0);
  unlock();
  await writer;
  assert.equal(await requestDeletion(db, 1, start), true);
  assert.equal(await readActiveSessionGeneration(db, 1), null);
  assert.equal(await requestDeletion(db, 1, start + 10), false);
  assert.equal(await claimDeletion(db, 1, due - 1), false);
  assert.equal(await restoreDeletion(db, 1, due - 1), true);
  assert.equal(await readActiveSessionGeneration(db, 1), 1);
  assert.equal(raw.prepare('SELECT is_del FROM user WHERE user_id = 1').get().is_del, 0);
  assert.equal(await requestDeletion(db, 2, start), true);
  assert.equal(await restoreDeletion(db, 2, due), false);
  assert.equal(await claimDeletion(db, 2, due), true);
  assert.equal(await claimDeletion(db, 2, due), false);
  assert.equal(await restoreDeletion(db, 2, due + 1), false);
  assert.equal(raw.prepare('SELECT is_del FROM user WHERE user_id = 2').get().is_del, 1);
  assert.equal(await requestDeletion(db, 99, start), false);
  assert.equal(await readActiveSessionGeneration(db, 99), null);
  raw.exec('INSERT INTO user (user_id) VALUES (3)');
  raw.exec("CREATE TRIGGER fail_request BEFORE INSERT ON account_deletion_request BEGIN SELECT RAISE(ABORT, 'simulated failure'); END");
  await assert.rejects(requestDeletion(db, 3, start));
  assert.equal(raw.prepare('SELECT is_del FROM user WHERE user_id = 3').get().is_del, 0);
  raw.close();
});
