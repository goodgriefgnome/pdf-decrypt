/**
 * Tests against PDFs encrypted by another tool (qpdf, through pikepdf: see make-fixtures.py), one
 * for each kind of encryption: each is decrypted with its user and its owner password, and must
 * then read as plain.pdf does (its pages' contents, title and author).
 * Run: npm test (after npm run build)
 */

const fs = require('fs');
const path = require('path');
const { decryptPDF } = require('../dist/index.js');
const { PDFDocument, PDFArray, PDFName, decodePDFRawStream } = require('pdf-lib');

const fixture = (name) => new Uint8Array(fs.readFileSync(path.join(__dirname, 'fixtures', name + '.pdf')));

/** Each page's contents, decoded */
function contents(doc) {
  return doc.getPages().map((page) => {
    const c = page.node.Contents();
    const streams = c instanceof PDFArray ? c.asArray().map((r) => doc.context.lookup(r)) : [c];
    return streams.map((s) => Buffer.from(decodePDFRawStream(s).decode()).toString('latin1')).join('\n');
  });
}

function assert(condition, message) {
  if (!condition) throw new Error('Assertion failed: ' + message);
}

const fixtures = [
  'rc4-40',
  'rc4-128',
  'rc4-128-objstm',
  'rc4-128-crypt-filter',
  'aes-128',
  'aes-128-owner-only',
  'aes-128-objstm',
  'aes-128-metadata-unencrypted',
  'aes-256-r5',
  'aes-256',
  'aes-256-objstm',
];

async function run() {
  console.log('Testing @pdfsmaller/pdf-decrypt against fixtures...\n');
  const plain = await PDFDocument.load(fixture('plain'));
  const expected = contents(plain);
  let passed = 0;
  let failed = 0;

  for (const name of fixtures) {
    const passwords = name.endsWith('owner-only') ? ['', 'owner'] : ['secret', 'owner'];
    for (const password of passwords) {
      const label = `${name}, password "${password}"`;
      try {
        const decrypted = await decryptPDF(fixture(name), password);
        const doc = await PDFDocument.load(decrypted);
        assert(doc.getPageCount() === 2, 'Should have 2 pages');
        assert(JSON.stringify(contents(doc)) === JSON.stringify(expected), 'Pages should read as before');
        assert(doc.getTitle() === 'Mass in G', `Title should be "Mass in G", not ${JSON.stringify(doc.getTitle())}`);
        assert(doc.getAuthor() === 'Franz Schubert', 'Author should be "Franz Schubert"');
        if (name.endsWith('metadata-unencrypted')) {
          const metadata = doc.catalog.lookup(PDFName.of('Metadata'));
          assert(Buffer.from(decodePDFRawStream(metadata).decode()).toString('utf8').includes('Mass in G'), 'Metadata should be left as it was');
        }
        console.log('  PASSED', label);
        passed++;
      } catch (e) {
        console.log('  FAILED', label + ':', e.message);
        failed++;
      }
    }
    if (name.endsWith('owner-only')) continue;
    try {
      await decryptPDF(fixture(name), 'wrong');
      console.log('  FAILED', name + ', wrong password: should have thrown');
      failed++;
    } catch (e) {
      if (e.message.includes('Incorrect password')) {
        console.log('  PASSED', name + ', wrong password');
        passed++;
      } else {
        console.log('  FAILED', name + ', wrong password:', e.message);
        failed++;
      }
    }
  }

  console.log(`\nFixtures: ${passed} passed, ${failed} failed\n`);
  if (failed > 0) process.exit(1);
}

run().catch((err) => {
  console.error('Test runner error:', err);
  process.exit(1);
});
