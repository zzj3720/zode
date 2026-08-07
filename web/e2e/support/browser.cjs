'use strict';

const fs = require('node:fs');

const { SecretLeakFailure } = require('./harness.cjs');

const INDEXED_DB_LIMITS = Object.freeze({
  maxDatabases: 16,
  maxStoresPerDatabase: 32,
  maxValuesPerStore: 64,
  maxValueChars: 16 * 1024,
  maxTotalChars: 512 * 1024,
  maxPreviewDepth: 4,
  maxPreviewProperties: 32,
});

function boundedInteger(value, fallback, maximum) {
  return Number.isInteger(value) ? Math.max(1, Math.min(value, maximum)) : fallback;
}

function indexedDbLimits(options = {}) {
  return {
    maxDatabases: boundedInteger(options.maxDatabases, INDEXED_DB_LIMITS.maxDatabases, 128),
    maxStoresPerDatabase: boundedInteger(options.maxStoresPerDatabase, INDEXED_DB_LIMITS.maxStoresPerDatabase, 128),
    maxValuesPerStore: boundedInteger(options.maxValuesPerStore, INDEXED_DB_LIMITS.maxValuesPerStore, 256),
    maxValueChars: boundedInteger(options.maxValueChars, INDEXED_DB_LIMITS.maxValueChars, 64 * 1024),
    maxTotalChars: boundedInteger(options.maxTotalChars, INDEXED_DB_LIMITS.maxTotalChars, 2 * 1024 * 1024),
    maxPreviewDepth: boundedInteger(options.maxPreviewDepth, INDEXED_DB_LIMITS.maxPreviewDepth, 8),
    maxPreviewProperties: boundedInteger(options.maxPreviewProperties, INDEXED_DB_LIMITS.maxPreviewProperties, 128),
  };
}

async function enumerateIndexedDb(page, options = {}) {
  const limits = indexedDbLimits(options);
  return page.evaluate(async (input) => {
    const result = { databases: [], unavailable: false, truncated: false, totalChars: 0 };
    if (typeof indexedDB === 'undefined' || typeof indexedDB.databases !== 'function') {
      result.unavailable = true;
      return result;
    }

    const preview = (value, depth = 0, seen = new WeakSet()) => {
      if (depth > input.maxPreviewDepth) return '[depth-limit]';
      if (value === null) return 'null';
      if (value === undefined) return 'undefined';
      if (typeof value === 'string') return value.slice(0, input.maxValueChars);
      if (typeof value === 'number' || typeof value === 'boolean' || typeof value === 'bigint') return String(value);
      if (typeof value !== 'object') return String(value);
      if (seen.has(value)) return '[circular]';
      seen.add(value);
      let output;
      try {
        if (Array.isArray(value)) {
          output = value.slice(0, input.maxPreviewProperties).map((entry) => preview(entry, depth + 1, seen));
          if (value.length > input.maxPreviewProperties) output.push('[items-truncated]');
        } else {
          output = {};
          let count = 0;
          for (const key in value) {
            if (!Object.prototype.hasOwnProperty.call(value, key)) continue;
            if (count >= input.maxPreviewProperties) {
              output.__properties_truncated__ = true;
              break;
            }
            output[key] = preview(value[key], depth + 1, seen);
            count += 1;
          }
        }
      } catch {
        output = '[unreadable]';
      }
      seen.delete(value);
      let text;
      try { text = typeof output === 'string' ? output : JSON.stringify(output); } catch { text = '[unserializable]'; }
      return String(text || '').slice(0, input.maxValueChars);
    };

    const openDatabase = (name) => new Promise((resolve) => {
      let request;
      try { request = indexedDB.open(name); } catch { resolve(null); return; }
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => resolve(null);
      request.onblocked = () => resolve(null);
    });

    const readStore = (database, name) => new Promise((resolve) => {
      const storeResult = { name, values: [] };
      let transaction;
      let settled = false;
      const finish = () => {
        if (settled) return;
        settled = true;
        resolve(storeResult);
      };
      try {
        transaction = database.transaction(name, 'readonly');
        const request = transaction.objectStore(name).openCursor();
        request.onerror = finish;
        request.onsuccess = () => {
          const cursor = request.result;
          if (!cursor) {
            finish();
            return;
          }
          if (storeResult.values.length >= input.maxValuesPerStore || result.totalChars >= input.maxTotalChars) {
            result.truncated = true;
            try { transaction.abort(); } catch {}
            return;
          }
          const key = preview(cursor.key);
          const value = preview(cursor.value);
          const size = key.length + value.length;
          if (result.totalChars + size > input.maxTotalChars) {
            result.truncated = true;
            try { transaction.abort(); } catch {}
            return;
          }
          storeResult.values.push({ key, value });
          result.totalChars += size;
          cursor.continue();
        };
        transaction.oncomplete = finish;
        transaction.onerror = finish;
        transaction.onabort = finish;
      } catch {
        storeResult.error = 'read_failed';
        finish();
      }
    });

    let entries;
    try {
      entries = await indexedDB.databases();
    } catch {
      result.unavailable = true;
      return result;
    }
    if (entries.length > input.maxDatabases) result.truncated = true;
    for (const entry of entries.slice(0, input.maxDatabases)) {
      if (!entry?.name) continue;
      const databaseResult = {
        name: entry.name,
        version: entry.version || 0,
        stores: [],
      };
      const database = await openDatabase(entry.name);
      if (!database) {
        databaseResult.error = 'open_failed';
        result.databases.push(databaseResult);
        continue;
      }
      try {
        const storeNames = Array.from(database.objectStoreNames);
        if (storeNames.length > input.maxStoresPerDatabase) result.truncated = true;
        for (const storeName of storeNames.slice(0, input.maxStoresPerDatabase)) {
          databaseResult.stores.push(await readStore(database, storeName));
          if (result.totalChars >= input.maxTotalChars) break;
        }
      } finally {
        database.close();
      }
      result.databases.push(databaseResult);
      if (result.totalChars >= input.maxTotalChars) break;
    }
    return result;
  }, limits);
}

class BrowserSecretGuard {
  constructor({ ledger, context }) {
    this.ledger = ledger;
    this.pages = new Set();
    this.contexts = new Set();
    this.consoleMessages = [];
    this.pageErrors = [];
    this.violations = [];
    if (context) this.attachContext(context);
  }

  inspect(value, surface) {
    const match = this.ledger.find(value);
    if (match) this.violations.push({ surface, label: match.label });
  }

  attachPage(page) {
    if (this.pages.has(page)) return;
    this.pages.add(page);
    page.on('console', (message) => {
      const text = message.text();
      this.consoleMessages.push(text);
      this.inspect(text, 'browser console');
    });
    page.on('pageerror', (error) => {
      const text = error.message || String(error);
      this.pageErrors.push(text);
      this.inspect(text, 'browser page error');
    });
    page.on('request', (request) => {
      this.inspect(request.url(), 'browser request URL');
      this.inspect(request.postData() || '', 'browser request body');
    });
    page.on('response', (response) => this.inspect(response.url(), 'browser response URL'));
    page.on('framenavigated', (frame) => this.inspect(frame.url(), 'browser navigation URL'));
    page.on('download', async (download) => {
      this.inspect(download.suggestedFilename(), 'browser download filename');
      try {
        const stream = await download.createReadStream();
        if (!stream) return;
        for await (const chunk of stream) this.inspect(chunk, 'browser downloaded artifact');
      } catch {
        this.violations.push({ surface: 'browser downloaded artifact', label: 'unreadable' });
      }
    });
  }

  attachContext(context) {
    if (!this.contexts.has(context)) {
      this.contexts.add(context);
      context.on('page', (page) => this.attachPage(page));
    }
    for (const page of context.pages()) this.attachPage(page);
  }

  async scanIndexedDb(page, options = {}) {
    const indexedDb = await enumerateIndexedDb(page, options);
    this.inspect(JSON.stringify(indexedDb), 'browser IndexedDB values');
    return indexedDb;
  }

  async scanPage(page) {
    this.attachPage(page);
    this.inspect(page.url(), 'browser page URL');
    const storage = await page.evaluate(async () => {
      const collect = (store) => Object.fromEntries(Array.from({ length: store.length }, (_, index) => {
        const key = store.key(index);
        return [key, store.getItem(key)];
      }));
      const databases = typeof indexedDB.databases === 'function'
        ? (await indexedDB.databases()).map((database) => database.name || '')
        : [];
      return {
        localStorage: collect(localStorage),
        sessionStorage: collect(sessionStorage),
        indexedDbNames: databases,
        cookie: document.cookie,
        bodyText: document.body?.innerText || '',
        accessibleAttributes: Array.from(document.querySelectorAll('[aria-label], [title], [alt]'))
          .map((element) => [element.getAttribute('aria-label'), element.getAttribute('title'), element.getAttribute('alt')]),
      };
    }).catch(() => undefined);
    if (!storage) return;
    this.inspect(JSON.stringify(storage.localStorage), 'browser localStorage');
    this.inspect(JSON.stringify(storage.sessionStorage), 'browser sessionStorage');
    this.inspect(JSON.stringify(storage.indexedDbNames), 'browser IndexedDB names');
    this.inspect(storage.cookie, 'browser document cookie');
    this.inspect(storage.bodyText, 'browser rendered text');
    this.inspect(JSON.stringify(storage.accessibleAttributes), 'browser accessible names');
    for (const cookie of await page.context().cookies()) {
      this.inspect(cookie.name, 'browser cookie name');
      this.inspect(cookie.value, 'browser cookie value');
    }
  }

  assertNoLeaks() {
    const first = this.violations[0];
    if (first) throw new SecretLeakFailure(first.surface, first.label);
  }

  async captureSafeScreenshot(page, testInfo) {
    const screenshotPath = testInfo.outputPath('failure-safe.png');
    try {
      await page.screenshot({ path: screenshotPath, fullPage: true });
      const match = this.ledger.find(fs.readFileSync(screenshotPath));
      if (match) {
        fs.unlinkSync(screenshotPath);
        this.violations.push({ surface: 'failure screenshot', label: match.label });
        return undefined;
      }
      return screenshotPath;
    } catch {
      try { fs.unlinkSync(screenshotPath); } catch {}
      return undefined;
    }
  }
}

module.exports = { BrowserSecretGuard, enumerateIndexedDb };
