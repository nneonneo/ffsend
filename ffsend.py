#!/usr/bin/env python

""" Interact with https://send.firefox.com.

Tested with Send version v3.0.21 (commit 2ccc044)
(see https://send.firefox.com/__version__)
"""

from __future__ import print_function

import os
from hashlib import sha256
import mimetypes
import base64
import json
import re
import hmac
import struct
import sys

from clint.textui.progress import Bar as ProgressBar
# AES.MODE_GCM requires PyCryptodome
try:
    from Cryptodome.Cipher import AES
    from Cryptodome.Protocol.KDF import PBKDF2
except ImportError:
    from Crypto.Cipher import AES
    from Crypto.Protocol.KDF import PBKDF2
import requests


### General utilities
def url_b64encode(s):
    return base64.urlsafe_b64encode(s).decode().rstrip('=')

def url_b64decode(s):
    # accept unicode (py2), str (py2) and str (py3) inputs
    s = str(s)
    s += '==='[(len(s) + 3) % 4:]
    return base64.urlsafe_b64decode(s)

### Cryptography
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

def derive_auth_key(secret, password=None, url=None):
    if password is None:
        return hkdf(64, secret, info=b'authentication')
    else:
        return PBKDF2(password.encode('utf8'), url.encode('utf8'), 64, 100,
                      lambda x, y: hmac.new(x, y, sha256).digest())

def create_meta_cipher(secret):
    meta_key = hkdf(16, secret, info=b'metadata')
    return AES.new(meta_key, AES.MODE_GCM, b'\x00' * 12, mac_len=16)

def file_cipher_generator(secret, salt):
    key = hkdf(16, secret, salt=salt, info=b'Content-Encoding: aes128gcm\0')
    nonce_base = hkdf(12, secret, salt=salt, info=b'Content-Encoding: nonce\0')
    seq = 0
    while True:
        if seq >= (1 << 32):
            raise ValueError("Tried to encrypt too many chunks!")
        tail, = struct.unpack('>I', nonce_base[-4:])
        tail ^= seq
        nonce = nonce_base[:-4] + struct.pack('>I', tail)
        yield AES.new(key, AES.MODE_GCM, nonce, mac_len=16)
        seq += 1

def encrypt_file_iter(secret, file, recordsize=65536):
    # 1 byte padding (minimum) + 16 byte tag
    padtaglen = 17
    assert recordsize > padtaglen, "record size too small"

    idlen = 0
    salt = os.urandom(16)
    header = struct.pack('>16sIB', salt, recordsize, idlen)
    yield header

    ciphergen = file_cipher_generator(secret, salt)
    chunksize = recordsize - padtaglen
    # this loop structure allows us to handle zero-byte files properly
    chunk = file.read(chunksize)
    while True:
        nextchunk = file.read(chunksize)
        # add padding
        if not nextchunk:
            # reached EOF, this is the last chunk
            chunk += b'\x02'
        else:
            chunk += b'\x01' + b'\x00' * (recordsize - len(chunk) - padtaglen)

        # encrypt and append GCM tag
        cipher = next(ciphergen)
        res = cipher.encrypt(chunk)
        res += cipher.digest()

        yield res

        if not nextchunk:
            break
        chunk = nextchunk

def decrypt_file_iter(secret, file):
    # ensure we read the whole header even if we get a short read
    header = bytearray()
    while len(header) < 21:
        chunk = file.read(21 - len(header))
        if not chunk:
            raise EOFError()
        header += chunk

    salt, recordsize, idlen = struct.unpack('>16sIB', header)
    # TODO handle nonzero idlen
    assert idlen == 0, "unexpected idlen"
    assert recordsize > 17, "record size too small"

    ciphergen = file_cipher_generator(secret, salt)
    while True:
        # try to get a full record if at all possible
        record = bytearray()
        while len(record) < recordsize:
            chunk = file.read(recordsize - len(record))
            if not chunk:
                break
            record += chunk
        if len(record) < 17:
            raise ValueError("Bad record received")
        record = bytes(record)

        cipher = next(ciphergen)
        res = cipher.decrypt(record[:-16])
        cipher.verify(record[-16:])

        # verify and remove padding
        res = res.rstrip(b'\x00')
        if res.endswith(b'\x01'):
            yield res[:-1]
        elif res.endswith(b'\x02'):
            # final block
            yield res[:-1]
            break
        else:
            raise ValueError("Bad padding")

### Low level API
class FFSendAPI(object):
    # TODO: support Firefox Accounts login
    ''' Low-level Send API wrappers.

    These are fairly thin wrappers around the API.
    Each function returns a requests.Response, and some have simple retry logic.
    '''

    def __init__(self, baseurl):
        self.baseurl = baseurl
        # map from file id to nonce
        self._nonce_cache = {}

    def _auth_header(self, auth_key, nonce):
        sig = hmac.new(auth_key, nonce, sha256).digest()
        return 'send-v1 ' + url_b64encode(sig)

    def _get_nonce(self, id):
        if id not in self._nonce_cache:
            resp = self.get_exists(id)
            resp.raise_for_status()
            self._set_nonce(id, resp)

        return self._nonce_cache[id]

    def _set_nonce(self, id, resp):
        header = resp.headers.get('WWW-Authenticate', None)
        if header and header.startswith('send-v1 '):
            self._nonce_cache[id] = base64.b64decode(header.split()[1])

    ### Basic endpoints
    def post_upload(self, metadata, auth_key, data):
        ''' POST /api/upload

        metadata: raw encrypted file metadata
        auth_key: file's new auth key
        data: raw encrypted file data to upload
        '''
        resp = requests.post(self.baseurl + 'api/upload',
                             data=data,
                             headers={
                                 'X-File-Metadata': url_b64encode(metadata),
                                 'Authorization': 'send-v1 ' + url_b64encode(auth_key),
                                 'Content-Type': 'application/octet-stream'})
        if resp.status_code == 200:
            id = resp.json()['id']
            self._set_nonce(id, resp)
        return resp

    def get_exists(self, id):
        ''' GET /api/exists/:id

        id: file id
        '''
        return requests.get(self.baseurl + "api/exists/" + id)

    def get_download(self, id, auth_key):
        ''' GET /api/download/:id

        id: file id
        auth_key: file's auth key

        Reading the resulting request will produce raw encrypted file data.
        '''
        # TODO configurable retries
        for i in range(5):
            nonce = self._get_nonce(id)
            resp = requests.get(self.baseurl + "api/download/" + id,
                                stream=True,
                                headers={'Authorization': self._auth_header(auth_key, nonce)})
            self._set_nonce(id, resp)
            if resp.status_code == 401:
                continue
            return resp
        return resp

    def get_metadata(self, id, auth_key):
        ''' GET /api/metadata/:id

        id: file id
        auth_key: file's auth key

        The response's json will include raw encrypted file metadata.
        '''

        # TODO configurable retries
        for i in range(5):
            nonce = self._get_nonce(id)
            resp = requests.get(self.baseurl + "api/metadata/" + id,
                                headers={'Authorization': self._auth_header(auth_key, nonce)})
            self._set_nonce(id, resp)
            if resp.status_code == 401:
                continue
            return resp
        return resp

    ### Owner-only endpoints
    def post_delete(self, id, owner_token):
        ''' POST /api/delete/:id

        id: file id
        owner_token: owner token from upload
        '''
        return requests.post(self.baseurl + 'api/delete/' + id,
                             headers={'Content-Type': 'application/json'},
                             json={'owner_token': owner_token})

    def post_password(self, id, owner_token, auth_key):
        ''' POST /api/password/:id

        id: file id
        owner_token: owner token from upload
        auth_key: file's new auth key
        '''
        return requests.post(self.baseurl + 'api/password/' + id,
                             headers={'Content-Type': 'application/json'},
                             json={'auth': url_b64encode(auth_key), 'owner_token': owner_token})

    def post_info(self, id, owner_token):
        ''' POST /api/info/:id

        id: file id
        owner_token: owner token from upload
        '''
        return requests.post(self.baseurl + 'api/info/' + id,
                             headers={'Content-Type': 'application/json'},
                             json={'owner_token': owner_token})

    def post_params(self, id, owner_token, new_params):
        ''' POST /api/params/:id

        id: file id
        owner_token: owner token from upload
        new_params: file's new parameters (e.g. download limit)
        '''
        params = new_params.copy()
        params['owner_token'] = owner_token
        return requests.post(self.baseurl + 'api/params/' + id,
                             headers={'Content-Type': 'application/json'},
                             json=params)

### Mid-level API
class FFSend(object):
    ''' High-level Pythonic methods for the Firefox Send API

    This class wraps the low-level API with appropriate cryptographic logic. '''

    def __init__(self, service):
        self.api = FFSendAPI(service)

    def upload(self, metadata, fileobj):
        ''' Upload a file to the service.

        metadata: metadata object for the file
        fileobj: file-like object (supporting .read) to upload

        Returns: (response JSON, secret)
        '''

        secret = os.urandom(16)

        auth_key = derive_auth_key(secret)
        meta_cipher = create_meta_cipher(secret)

        metadata = meta_cipher.encrypt(json.dumps(metadata).encode('utf8'))
        metadata += meta_cipher.digest()

        data = encrypt_file_iter(secret, fileobj)
        resp = self.api.post_upload(metadata, auth_key, data)
        resp.raise_for_status()

        return resp.json(), secret

    def download(self, fid, secret, fileobj, password=None, url=None):
        ''' Download a file from the service.

        fid: file ID
        secret: end-to-end encryption secret
        fileobj: file-like object (supporting .write) to write to
        password: file password (optional)
        url: file share URL (must be specified if password is specified)
        '''
        auth_key = derive_auth_key(secret, password, url)

        resp = self.api.get_download(fid, auth_key)
        for chunk in decrypt_file_iter(secret, resp.raw):
            fileobj.write(chunk)

    def get_metadata(self, fid, secret, password=None, url=None):
        ''' Get file metadata.

        fid: file ID
        secret: end-to-end encryption secret
        password: file password (optional)
        url: file share URL (must be specified if password is specified)
        '''

        auth_key = derive_auth_key(secret, password, url)
        meta_cipher = create_meta_cipher(secret)

        resp = self.api.get_metadata(fid, auth_key)
        resp.raise_for_status()
        metadata = resp.json()

        md = url_b64decode(metadata['metadata'])
        md, mdtag = md[:-16], md[-16:]
        md = meta_cipher.decrypt(md)
        meta_cipher.verify(mdtag)
        metadata['metadata'] = json.loads(md)

        return metadata

    def owner_delete(self, fid, owner_token):
        ''' Delete a file (owners only)

        fid: file ID
        owner_token: owner token returned by upload
        '''
        resp = self.api.post_delete(fid, owner_token)
        resp.raise_for_status()

    def owner_get_info(self, fid, owner_token):
        ''' Get file basic info (# of downloads, time remaining; owners only)

        fid: file ID
        owner_token: owner token returned by upload
        '''
        resp = self.api.post_info(fid, owner_token)
        resp.raise_for_status()
        return resp.json()

    def owner_set_password(self, fid, owner_token, secret, password=None, url=None):
        ''' Set a new password for the file (owners only)

        fid: file ID
        owner_token: owner token returned by upload
        secret: end-to-end encryption secret
        password: new file password (optional - if unset it removes the password)
        url: file share URL (must be specified if password is specified)
        '''
        new_auth_key = derive_auth_key(secret, password, url)
        resp = self.api.post_password(fid, owner_token, new_auth_key)
        resp.raise_for_status()

    def owner_set_params(self, fid, owner_token, new_params):
        ''' Set new parameters for the file (e.g. download limit; owners only)

        fid: file ID
        owner_token: owner token returned by upload
        new_params: new parameters as a json-compatible dict
        '''
        resp = self.api.post_params(fid, owner_token, new_params)
        resp.raise_for_status()

def single_file_metadata(filename, filesize, mimetype='application/octet-stream'):
    return {"name": filename, "size": filesize, "type": mimetype, "manifest": {"files": [
        {"name": filename, "size": filesize, "type": mimetype}]}}

### High-level CLI
def parse_url(url):
    secret = None
    m = re.match(r'^https://(.*)/download/(\w+)/?#?([\w_-]+)?$', url)
    if m:
        service = 'https://' + m.group(1) + '/'
        fid = m.group(2)
        if m.group(3):
            secret = url_b64decode(m.group(3))
    else:
        raise Exception("Failed to parse URL %s" % url)

    return service, fid, secret

def _upload(service, filename, file, password=None):
    filename = os.path.basename(filename)

    send = FFSend(service)

    mimetype = mimetypes.guess_type(filename, strict=False)[0] or 'application/octet-stream'
    print("Uploading as mimetype", mimetype)
    file.seek(0, 2)
    filesize = file.tell()
    file.seek(0)

    metadata = single_file_metadata(filename, filesize, mimetype=mimetype)

    bar = ProgressBar(expected_size=filesize or 1, filled_char='=')

    class FakeFile:
        def read(self, sz=None):
            res = file.read(sz)
            bar.show(file.tell())
            return res

    res, secret = send.upload(metadata, FakeFile())
    print()
    url = res['url'] + '#' + url_b64encode(secret)
    owner_token = res['owner']

    if password is not None:
        service, fid, secret = parse_url(url)
        send.owner_set_password(fid, owner_token, secret, password, url)

    print("Your download link is", url)
    print("Owner token is", owner_token)
    return url, owner_token

def upload(service, filename, file=None, password=None):
    ''' Upload a file to the Send service.

    service: base URL for the service
    filename: filename to upload
    file: readable file-like object (supporting .read, .seek, .tell)
        if not specified, defaults to opening `filename`
    password: optional password to protect the file

    returns the share URL and owner token for the file
    '''

    if file is None:
        with open(filename, "rb") as file:
            return _upload(service, filename, file, password)
    else:
        return _upload(service, filename, file, password)

def delete(service, fid, token):
    FFSend(service).owner_delete(fid, token)

def set_params(service, fid, token, **params):
    FFSend(service).owner_set_params(fid, token, params)

def get_metadata(service, fid, secret, password=None, url=None):
    return FFSend(service).get_metadata(fid, secret, password, url)

def get_owner_info(service, fid, token):
    return FFSend(service).owner_get_info(fid, token)

def download(service, fid, secret, dest, password=None, url=None):
    send = FFSend(service)
    metadata = send.get_metadata(fid, secret, password, url)

    filename = metadata['metadata']['name']

    if os.path.isdir(dest):
        filename = os.path.join(dest, filename)
    else:
        filename = dest

    print("Downloading to %s..." % filename)

    try:
        with open(filename + '.tmp', 'wb') as outf:
            bar = ProgressBar(expected_size=metadata['metadata']['size'] or 1, filled_char='=')

            class FakeFile:
                def write(self, data):
                    res = outf.write(data)
                    bar.show(outf.tell())
                    return res

            send.download(fid, secret, FakeFile(), password, url)

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
    group.add_argument('-s', '--service', help="Send Service to use, default to https://send.firefox.com/",
                       default="https://send.firefox.com/")
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

def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
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
        if re.match(r'.*/$', args.service) is None:
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
        metadata = get_metadata(service, fid, secret, args.password, args.target)
        print("Service %s:" % service)
        print("File ID %s:" % fid)
        print(metadata)
        print("  Filename:", metadata['metadata']['name'])
        print("  MIME type:", metadata['metadata']['type'])
        if 'manifest' in metadata['metadata']:
            print("  Manifest:", metadata['metadata']['manifest'])
        print("  Size:", metadata['metadata']['size'])
        print("  Final download:", "yes" if metadata['finalDownload'] else "no")
        ttl = metadata['ttl']
        h, ttl = divmod(ttl, 3600000)
        m, ttl = divmod(ttl, 60000)
        s, ttl = divmod(ttl, 1000)
        print("  Expires in: %dh%dm%ds" % (h, m, s))
        if args.token:
            info = get_owner_info(service, fid, args.token)
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
    exit(main())
