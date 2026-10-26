/**
 * Writes test/fixtures/plain.pdf, the unencrypted PDF the fixtures are made from (see
 * make-fixtures.py): two pages of text, and a title and author in its document information.
 * Run: node test/make-source.js
 */

const fs = require('fs');
const path = require('path');
const { PDFDocument, StandardFonts } = require('pdf-lib');

(async () => {
  const doc = await PDFDocument.create();
  doc.setTitle('Mass in G');
  doc.setAuthor('Franz Schubert');
  const font = await doc.embedFont(StandardFonts.Helvetica);
  for (const text of ['Kyrie eleison', 'Gloria in excelsis']) {
    doc.addPage([595, 842]).drawText(text, { x: 60, y: 760, size: 24, font });
  }
  const bytes = await doc.save({ useObjectStreams: false });
  fs.writeFileSync(path.join(__dirname, 'fixtures', 'plain.pdf'), bytes);
})();
