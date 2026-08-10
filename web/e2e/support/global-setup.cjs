'use strict';

const fs = require('node:fs');
const path = require('node:path');

module.exports = async function globalSetup() {
  const incidents = path.resolve(__dirname, '../fixtures/incidents');
  if (!fs.existsSync(incidents)) return;
  for (const name of fs.readdirSync(incidents)) {
    if (!name.endsWith('.v1.json')) continue;
    fs.chmodSync(path.join(incidents, name), 0o444);
  }
};
