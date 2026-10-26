"""
Writes the encrypted fixtures in test/fixtures from plain.pdf (see make-source.js), one for each
kind of encryption, with qpdf (through pikepdf: pip install pikepdf). The user password is
"secret" and the owner password "owner", except in *-owner-only.pdf, which has no user password
(anyone can open it; it only limits what may be done with it). The *-objstm.pdf ones keep their
objects in object streams. Run: python3 test/make-fixtures.py
"""

import os
import pikepdf

here = os.path.join(os.path.dirname(__file__), 'fixtures')
source = os.path.join(here, 'plain.pdf')

fixtures = {
    'rc4-40': dict(R=2),
    'rc4-128': dict(R=3),
    'rc4-128-crypt-filter': dict(R=4, aes=False),
    'aes-128': dict(R=4),
    'aes-128-owner-only': dict(R=4, user=''),
    'aes-128-objstm': dict(R=4, objstm=True),
    'aes-128-metadata-unencrypted': dict(R=4, metadata=False, xmp=True),
    'aes-256-r5': dict(R=5),
    'aes-256': dict(R=6),
    'aes-256-objstm': dict(R=6, objstm=True),
    'rc4-128-objstm': dict(R=3, objstm=True),
}

for name, f in fixtures.items():
    with pikepdf.open(source) as pdf:
        if f.get('xmp'):
            # pikepdf writes the document information from the XMP metadata: the author too.
            with pdf.open_metadata() as meta:
                meta['dc:title'] = 'Mass in G'
                meta['dc:creator'] = ['Franz Schubert']
        kwargs = dict(R=f['R'], user=f.get('user', 'secret'), owner='owner')
        # pikepdf takes AES only from R=4 on (where it is the default), and the choice to leave
        # metadata unencrypted only with AES; without, the metadata is encrypted with the rest.
        kwargs['aes'] = f.get('aes', True) if f['R'] >= 4 else False
        kwargs['metadata'] = f.get('metadata', True) if kwargs['aes'] else False
        pdf.save(
            os.path.join(here, name + '.pdf'),
            encryption=pikepdf.Encryption(**kwargs),
            object_stream_mode=pikepdf.ObjectStreamMode.generate if f.get('objstm') else pikepdf.ObjectStreamMode.disable,
            # The same ID each time, so the fixtures only change when this does.
            static_id=True,
        )
    print('wrote', name)
