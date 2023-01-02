const express = require('express');
const app = express();

const fs = require('fs');
const sqlite3 = require('sqlite3');

if (!fs.existsSync('database.db')) {
  console.log('[WEBAPP] Creating database file');

  fs.writeFile('database.db', '', (err) => {
    if (err) {
      console.error('WEBAPP] Error creating database file');
      process.exit(1);
    }
  });

  const db = new sqlite3.Database('database.db');
  
  const createUsersTable = `
  CREATE TABLE IF NOT EXISTS scan_data (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url VARCHAR(255) NOT NULL UNIQUE,
    platform VARCHAR(255) NOT NULL,
    json LONGTEXT DEFAULT '{}',
    vuln_rating INT(100) NOT NULL
  );
  `;

  const createPostsTable = `CREATE TABLE IF NOT EXISTS database_setup (
    id INTEGER PRIMARY KEY
  );`;

  db.run(createUsersTable, (err) => {
    if (err) {
      console.error(err.message);
      process.exit(1);
    }
  });

  db.run(createPostsTable, (err) => {
    if (err) {
      console.error(err.message);
      process.exit(1);
    }
  });

  db.close();

  console.log('[WEBAPP] database file created');

} else {

  const db = new sqlite3.Database('database.db');

  db.get('SELECT name FROM sqlite_master WHERE type=\'table\' AND name=\'database_setup\'', (err, row) => {
    if (err) {
      console.error(err.message);
    }
    if (!row) {
      console.log('[WEBAPP] Fixing database file');

      const db = new sqlite3.Database('database.db');
  
      const createUsersTable = `
      CREATE TABLE IF NOT EXISTS scan_data (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url VARCHAR(255) NOT NULL UNIQUE,
        platform VARCHAR(255) NOT NULL,
        json LONGTEXT DEFAULT '{}',
        vuln_rating INT(100) NOT NULL
      );
      `;

      const createPostsTable = `CREATE TABLE IF NOT EXISTS database_setup (
        id INTEGER PRIMARY KEY
      );`;

      db.run(createUsersTable, (err) => {
        if (err) {
          console.error(err.message);
          process.exit(1);
        }
      });

      db.run(createPostsTable, (err) => {
        if (err) {
          console.error(err.message);
          process.exit(1);
        }
      });

      db.close();

      console.log('[WEBAPP] database file fixed');
    } else {
    }
  });
  
  db.close();
}


// Set the view engine to EJS
app.set('view engine', 'ejs');

app.get('/', (req, res) => {

  const sqlite3 = require('sqlite3').verbose();
  const db = new sqlite3.Database('database.db');

  db.all('SELECT * FROM scan_data', (err, rows) => {
    if (err) {
      console.error(err.message);
    }
    res.render('dashboard', {rows: rows});
  });
});

app.get('/recon', (req, res) => {
  res.render('recon');
});

app.post('/recon/:url', (req, res) => {

  const { spawn } = require('child_process');

  const py = spawn('python', ['functions.py', req.params.url]);

  py.stdout.on('data', (data) => {
    jsonData = JSON.parse(data)

    const sqlite3 = require('sqlite3').verbose();
    const db = new sqlite3.Database('database.db');

    const stmt = `
    INSERT OR REPLACE INTO scan_data (url, platform, json, vuln_rating)
    VALUES (?, ?, ?, ?)
    `;

    let vuln_rating = 0;

    if (jsonData['unsecure_jwt'] != null) {
      vuln_rating += 20;
    }

    if (jsonData['prototype_pollution'] != null) {
      vuln_rating += 10;
    }

    if (jsonData['xss'] != null) {
      vuln_rating += 5;
    }

    if (jsonData['cors'] != null && '*' in jsonData['cors']) {
      vuln_rating += 5;
    }

    if (jsonData['prototype_pollution'] != null && ['null', 'Shopify'].indexOf(jsonData['prototype_pollution']) !== -1) {
      vuln_rating += 5;
    }

    if (jsonData['form_security'].some(obj => obj.sql_injection === true)) {
      vuln_rating += 5;
    }

    if (jsonData['form_security'].some(obj => obj.csrf_token != null)) {
      vuln_rating -= 15;
    }

    const params = [jsonData['site'], jsonData['platform'] || 'Unknown', JSON.stringify(jsonData), vuln_rating];

    db.run(stmt, params, (err) => {
      if (err) {
        console.error(err.message);
      }
    });

    db.close();

    res.json({
      Site: jsonData['site'], 
      Platform: jsonData['platform'], 
      Data: jsonData, 
      rating: vuln_rating
    });
  });

  py.stderr.on('data', (data) => {
    console.error(`stderr: ${data}`);
  });

});

app.listen(3000, () => {
  console.log(`
  Server running
  Please open your browser at http://localhost:3000
  `);
});