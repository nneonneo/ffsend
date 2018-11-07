#!/usr/bin/env python

""" Interact with https://send.firefox.com """

from __future__ import print_function

import os
from hashlib import sha256
import mimetypes
import base64
import json
import re
import hmac
from io import BytesIO

from clint.textui.progress import Bar as ProgressBar
# AES.MODE_GCM requires PyCryptodome
try:
    from Cryptodome.Cipher import AES
    from Cryptodome.Protocol.KDF import PBKDF2
except ImportError:
    from Crypto.Cipher import AES
    from Crypto.Protocol.KDF import PBKDF2
import requests
from requests_toolbelt.multipart.encoder import MultipartEncoder, MultipartEncoderMonitor, total_len


def b64encode(s):
    return base64.urlsafe_b64encode(s).decode().rstrip('=')

def b64decode(s):
    # accept unicode (py2), str (py2) and str (py3) inputs
    s = str(s)
    s += '==='[(len(s) + 3) % 4:]
    return base64.urlsafe_b64decode(s)

def hkdf(length, ikm, hashfunc=sha256, salt=b"", info=b""):
    prk = hmac.new(salt, ikm, hashfunc).digest()
    t = b""
    i = 0
    okm = bytearray()
    while len(okm) < length:
        i += 1
        t = hmac.new(prk, t + info + bytes(bytearray([i])), hashfunc).digest()
        okm += t
    return bytes(okm[:length])

def deriveFileKey(secret):
    return hkdf(16, secret, info=b'encryption')

def deriveAuthKey(secret, password=None, url=None):
    if password is None:
        return hkdf(64, secret, info=b'authentication')
    return PBKDF2(password.encode('utf8'), url.encode('utf8'), 64, 100,
                  lambda x, y: hmac.new(x, y, sha256).digest())

def deriveMetaKey(secret):
    return hkdf(16, secret, info=b'metadata')

def parse_url(url):
    secret = None
    m = re.match(r'^https://(.*)/download/(\w+)/?#?([\w_-]+)?$', url)
    if m:
        service = 'https://' + m.group(1) + '/'
        fid = m.group(2)
        if m.group(3):
            secret = b64decode(m.group(3))
    else:
        fid = url

    return service, fid, secret

def parse_nonce(headers):
    return base64.b64decode(headers['WWW-Authenticate'].split()[1])

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

def _upload(service, filename, file, password=None):
    filename = os.path.basename(filename)

    secret = os.urandom(16)
    iv = os.urandom(12)

    encryptKey = deriveFileKey(secret)
    authKey = deriveAuthKey(secret)
    metaKey = deriveMetaKey(secret)

    fileCipher = AES.new(encryptKey, AES.MODE_GCM, iv, mac_len=16)
    metaCipher = AES.new(metaKey, AES.MODE_GCM, b'\x00' * 12, mac_len=16)

    mimetype = mimetypes.guess_type(filename, strict=False)[0] or 'application/octet-stream'
    print("Uploading as mimetype", mimetype)

    metadata = {"iv": b64encode(iv), "name": filename, "type": mimetype}
    metadata = metaCipher.encrypt(json.dumps(metadata).encode('utf8'))
    metadata += metaCipher.digest()

    mpenc = MultipartEncoder(
        fields={'data': (filename,
                         LazyEncryptedFileWithTag(file, fileCipher, taglen=16),
                         'application/octet-stream')})
    mpmon = MultipartEncoderMonitor(mpenc, callback=upload_progress_callback(mpenc))
    resp = requests.post(service + 'api/upload', data=mpmon,
                         headers={
                             'X-File-Metadata': b64encode(metadata),
                             'Authorization': 'send-v1 ' + b64encode(authKey),
                             'Content-Type': mpmon.content_type})
    print()
    resp.raise_for_status()
    res = resp.json()
    url = res['url'] + '#' + b64encode(secret)
    ownerToken = res['owner']

    if password is not None:
        service, fid, secret = parse_url(url)
        newAuthKey = deriveAuthKey(secret, password, url)
        resp = requests.post(service + 'api/password/' + fid,
                             headers={'Content-Type': 'application/json'},
                             json={'auth': b64encode(newAuthKey), 'owner_token': ownerToken})
        resp.raise_for_status()

    print("Your download link is", url)
    print("Owner token is", ownerToken)
    return url, res['owner']

def upload(service, filename, file=None, password=None):
    if file is None:
        with open(filename, "rb") as file:
            return _upload(service, filename, file, password)
    else:
        return _upload(service, filename, file, password)

def delete(service, fid, token):
    req = requests.post(service + 'api/delete/' + fid, json={'owner_token': token})
    req.raise_for_status()

def set_params(service, fid, token, **params):
    params['owner_token'] = token
    req = requests.post(service + 'api/params/' + fid, json=params)
    req.raise_for_status()

def get_metadata(service, fid, secret, password=None, url=None):
    authKey = deriveAuthKey(secret, password, url)
    metaKey = deriveMetaKey(secret)
    metaCipher = AES.new(metaKey, AES.MODE_GCM, b'\x00' * 12, mac_len=16)

    url = service + "download/" + fid
    resp = requests.get(url)
    resp.raise_for_status()
    nonce = parse_nonce(resp.headers)

    sig = hmac.new(authKey, nonce, sha256).digest()
    url = service + "api/metadata/" + fid
    resp = requests.get(url, headers={'Authorization': 'send-v1 ' + b64encode(sig)})
    resp.raise_for_status()
    metadata = resp.json()

    md = b64decode(metadata['metadata'])
    md, mdtag = md[:-16], md[-16:]
    md = metaCipher.decrypt(md)
    metaCipher.verify(mdtag)
    metadata['metadata'] = json.loads(md)

    # return metadata and next nonce
    return metadata, parse_nonce(resp.headers)

def get_owner_info(service, fid, token):
    req = requests.post(service + 'api/info/' + fid, json={'owner_token': token})
    req.raise_for_status()
    return req.json()

def download(service, fid, secret, dest, password=None, url=None):
    metadata, nonce = get_metadata(service, fid, secret, password, url)

    encryptKey = deriveFileKey(secret)
    authKey = deriveAuthKey(secret, password, url)

    sig = hmac.new(authKey, nonce, sha256).digest()
    url = service + "api/download/" + fid
    resp = requests.get(url, headers={'Authorization': 'send-v1 ' + b64encode(sig)}, stream=True)
    resp.raise_for_status()

    flen = int(resp.headers.get('Content-Length'))
    filename = metadata['metadata']['name']

    if os.path.isdir(dest):
        filename = os.path.join(dest, filename)
    else:
        filename = dest

    iv = b64decode(metadata['metadata']['iv'])
    cipher = AES.new(encryptKey, AES.MODE_GCM, iv, mac_len=16)

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

    group = parser.add_argument_group('Common options')
    group.add_argument('target', help="URL to download or file to upload")
    group.add_argument('-p', '--password', help="Password to use")
    group.add_argument('-s', '--service', help="Send Service to use, default at https://send.firefox.com/", default="https://send.firefox.com/")
    group.add_argument('-o', '--output', help="Output directory or file; only relevant for download")

    group = parser.add_argument_group('General actions')
    group.add_argument('-i', '--info', action='store_true',
                       help="Get information on file. Target can be a URL or a plain file ID.")

    group = parser.add_argument_group('Owner actions')
    group.add_argument('-t', '--token',
                       help="Owner token to manage the file. Target can be a URL or a plain file ID.")
    group.add_argument('--delete', help="Delete the file. Must specify -t/--token", action='store_true')
    group.add_argument('--set-ttl', help="Set the time to live (in seconds). Must specify -t/--token", type=int)
    group.add_argument('--set-dlimit', help="Set the download limit. Must specify -t/--token", type=int)

    return parser.parse_args(argv), parser

def main(argv):
    args, parser = parse_args(argv)

    def do_set_params():
        params = {}
        if args.set_ttl is not None:
            params['ttl'] = args.set_ttl * 1000
        if args.set_dlimit is not None:
            params['dlimit'] = args.set_dlimit
        if params:
            if not args.token:
                parser.error("setting parameters requires -t/--token")
            set_params(service, fid, args.token, **params)
            print("File parameters %s set" % str(params))
            return True
        return False

    if os.path.exists(args.target):
        if args.info or args.token or args.output:
            parser.error("-i/-t/-o must not be specified with an upload")
        if re.match(r'.*/$', args.service) == None:
            args.service += '/'
        print("Uploading %s to %s ..." % (args.target, args.service))
        url, args.token = upload(args.service, args.target, password=args.password)
        service, fid, secret = parse_url(url)
        do_set_params()
        return

    service, fid, secret = parse_url(args.target)

    if args.info:
        if args.delete:
            parser.error("--info and --delete are mutually exclusive")
        metadata, nonce = get_metadata(service, fid, secret, args.password, args.target)
        print("Service %s:" % service)
        print("File ID %s:" % fid)
        print("  Filename:", metadata['metadata']['name'])
        print("  MIME type:", metadata['metadata']['type'])
        print("  Size:", metadata['size'])
        print("  Final download:", "yes" if metadata['finalDownload'] else "no")
        ttl = metadata['ttl']
        h, ttl = divmod(ttl, 3600000)
        m, ttl = divmod(ttl, 60000)
        s, ttl = divmod(ttl, 1000)
        print("  Expires in: %dh%dm%ds" % (h, m, s))
        if args.token:
            info = get_owner_info(fid, args.token)
            print("  Download limit:", info['dlimit'])
            print("  Downloads so far:", info['dtotal'])
        do_set_params()
        return
    elif args.delete:
        if not args.token:
            parser.error("--delete requires -t/--token")
        if args.set_ttl is not None or args.set_dlimit is not None:
            parser.error("--delete can't be set with set_ttl or set_dlimit")
        delete(service, fid, args.token)
        print("File deleted.")
        return

    if do_set_params():
        return

    if secret:
        print("Downloading %s..." % args.target)
        download(service, fid, secret, args.output or '.', args.password, args.target)
    else:
        # Assume they tried to upload a nonexistent file
        raise OSError("File %s does not exist" % args.target)


if __name__ == '__main__':
    import sys
    exit(main(sys.argv[1:]))
