#!/usr/bin/env python

""" Interact with https://send.firefox.com """

from __future__ import print_function

import os
from hashlib import sha256
import mimetypes
import binascii
import base64
import json
import re
from io import BytesIO

from clint.textui.progress import Bar as ProgressBar
try:
    from Cryptodome.Cipher import AES
except:
    from Crypto.Cipher import AES
# AES.MODE_GCM requires PyCryptodome
import requests
from requests_toolbelt.multipart.encoder import MultipartEncoder, MultipartEncoderMonitor, total_len


class LazyEncryptedFileWithTag:
    ''' File-like object that encrypts data on the fly, with a GCM tag appended.

    Suitable for use with MultipartEncoder. '''

    def __init__(self, file, cipher, taglen=16):
        self.file = file
        self.size = total_len(file) + taglen
        file.seek(0)
        self.fpos = 0

        self.cipher = cipher
        self.taglen = taglen
        self.tagio = None

    @property
    def len(self):
        ''' file.len for MultipartEncoder '''
        return self.size - self.fpos

    def read(self, size=-1):
        chunk = self.file.read(size)
        if chunk:
            chunk = self.cipher.encrypt(chunk)

        if size == -1 or size is None:
            tagread = -1
        else:
            tagread = size - len(chunk)

        if tagread:
            if self.tagio is None:
                tag = self.cipher.digest()
                assert len(tag) == self.taglen
                self.tagio = BytesIO(tag)
            chunk += self.tagio.read(tagread)

        self.fpos += len(chunk)

        return chunk

def upload_progress_callback(encoder):
    encoder_len = total_len(encoder)
    bar = ProgressBar(expected_size=encoder_len, filled_char='=')

    def callback(monitor):
        bar.show(monitor.bytes_read)

    return callback

def upload(filename, file=None):
    if file is None:
        file = open(filename, "rb")
    filename = os.path.basename(filename)

    print("Uploading %s..." % filename)
    key = os.urandom(16)
    iv = os.urandom(12)
    cipher = AES.new(key, AES.MODE_GCM, iv, mac_len=16)

    metadata = {"id": binascii.hexlify(iv).decode(), "filename": filename}
    mimetype = mimetypes.guess_type(filename, strict=False)[0] or 'application/octet-stream'
    print("Uploading as mimetype", mimetype)
    mpenc = MultipartEncoder(
        fields={'data': (filename, LazyEncryptedFileWithTag(file, cipher, taglen=16), mimetype)})
    mpmon = MultipartEncoderMonitor(mpenc, callback=upload_progress_callback(mpenc))
    req = requests.post('https://send.firefox.com/api/upload', data=mpmon,
        headers={
            'X-File-Metadata': json.dumps(metadata),
            'Content-Type': mpmon.content_type})
    print()
    req.raise_for_status()
    res = req.json()

    url = res['url'] + '#' + base64.urlsafe_b64encode(key).decode().rstrip('=')
    print("Your download link is", url)
    return url

def download(url, dest):
    m = re.match(r'^https://send.firefox.com/download/(\w+)/#([\w_-]+)$', url)
    if not m:
        raise ValueError("URL format appears to be incorrect")

    fid = m.group(1)
    key = base64.urlsafe_b64decode(m.group(2) + '==')

    print("Downloading %s..." % url)
    url = "https://send.firefox.com/api/download/" + fid
    resp = requests.get(url, stream=True)
    resp.raise_for_status()
    flen = int(resp.headers.get('Content-Length'))

    metadata = json.loads(resp.headers.get('X-File-Metadata'))
    filename = metadata['filename']

    if os.path.isdir(dest):
        filename = os.path.join(dest, filename)
    else:
        filename = dest

    iv = binascii.unhexlify(metadata['id'])
    cipher = AES.new(key, AES.MODE_GCM, iv)

    ho = sha256()

    print("Downloading to %s..." % filename)

    try:
        with open(filename + '.tmp', 'wb') as outf:
            bar = ProgressBar(expected_size=flen, filled_char='=')

            dl = 0
            tag = b''
            taglen = 16
            for data in resp.iter_content(chunk_size=8192):
                dl += len(data)
                bar.show(dl)

                if dl > flen - taglen:
                    dend = max(len(data) - (dl - (flen - taglen)), 0)
                    tag += data[dend:]
                    data = data[:dend]

                chunk = cipher.decrypt(data)
                ho.update(chunk)
                outf.write(chunk)
                if len(tag) == taglen:
                    break

            print()
            cipher.verify(tag)
    except Exception as e:
        print("File download failed:", e)
        os.unlink(filename + '.tmp')
    else:
        os.rename(filename + '.tmp', filename)
        print("Done, file verified!")

def parse_args(argv):
    import argparse

    parser = argparse.ArgumentParser(description="Download or upload a file to Firefox Send")
    parser.add_argument('target', help="URL to download or file to upload")
    parser.add_argument('-o', '--output', help="Output directory or file; only relevant for download")

    return parser.parse_args(argv)

def main(argv):
    args = parse_args(argv)

    if os.path.exists(args.target):
        upload(args.target)
    elif args.target.startswith('https://'):
        download(args.target, args.output or '.')
    else:
        # Assume they tried to upload a nonexistent file
        raise OSError("File %s does not exist" % args.target)

if __name__ == '__main__':
    import sys
    exit(main(sys.argv[1:]))
