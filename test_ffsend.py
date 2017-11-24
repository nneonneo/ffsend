import unittest
import ffsend
import tempfile
import random
import os
import shutil
import requests

FFSendError = requests.HTTPError

class TestFFSend(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.data_tiny = os.urandom(random.getrandbits(4))
        self.password = ''.join(random.choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') for _ in range(random.randint(1, 16)))
        self.origdir = os.getcwd()
        os.chdir(self.tmpdir)

    def tearDown(self):
        os.chdir(self.origdir)
        shutil.rmtree(self.tmpdir)

    def do_test(self, filename, data, password=None):
        with open(filename, 'wb') as f:
            f.write(data)

        url, token = ffsend.upload(filename, password=password)
        self.assertTrue(url is not None)
        os.unlink(filename)

        fid, secret = ffsend.parse_url(url)
        self.assertTrue(secret is not None)

        metadata, nonce = ffsend.get_metadata(fid, secret, password, url)
        self.assertEqual(metadata['metadata']['name'], filename)
        # + 16 for the GCM tag
        self.assertEqual(metadata['size'], len(data) + 16)

        ffsend.download(fid, secret, '.', password, url)
        with open(filename, 'rb') as f:
            self.assertEqual(data, f.read())

    def test_empty(self):
        self.do_test('empty.bin', b'')

    def test_tiny(self):
        self.do_test('tiny.bin', self.data_tiny)

    def test_small(self):
        self.do_test('small.bin', os.urandom(random.getrandbits(16)))

    def test_big(self):
        self.do_test('big.bin', os.urandom((1<<20) + random.getrandbits(20)))


    def test_empty_pw(self):
        self.do_test('empty.bin', b'', self.password)

    def test_tiny_pw(self):
        self.do_test('tiny.bin', self.data_tiny, self.password)

    def test_small_pw(self):
        self.do_test('small.bin', os.urandom(random.getrandbits(16)), self.password)

    def test_big_pw(self):
        self.do_test('big.bin', os.urandom((1<<20) + random.getrandbits(20)), self.password)


    def test_delete(self):
        with open('delete.bin', 'wb') as f:
            f.write(self.data_tiny)

        url, token = ffsend.upload('delete.bin')
        self.assertTrue(url is not None)
        os.unlink('delete.bin')

        fid, secret = ffsend.parse_url(url)
        ffsend.delete(fid, token)

        with self.assertRaises(FFSendError):
            ffsend.download(fid, secret, '.')

    def test_bad_delete(self):
        with open('delete.bin', 'wb') as f:
            f.write(self.data_tiny)

        url, token = ffsend.upload('delete.bin')
        self.assertTrue(url is not None)
        os.unlink('delete.bin')

        fid, secret = ffsend.parse_url(url)
        ffsend.download(fid, secret, '.')

        with self.assertRaises(FFSendError):
            ffsend.delete(fid, token)

    def test_delete_pw(self):
        with open('delete.bin', 'wb') as f:
            f.write(self.data_tiny)

        url, token = ffsend.upload('delete.bin', password='password')
        self.assertTrue(url is not None)
        os.unlink('delete.bin')

        fid, secret = ffsend.parse_url(url)
        ffsend.delete(fid, token)

        with self.assertRaises(FFSendError):
            ffsend.download(fid, secret, '.', 'password', url)

    def test_no_pw(self):
        with open('nopw.bin', 'wb') as f:
            f.write(self.data_tiny)

        url, token = ffsend.upload('nopw.bin', password='password')
        self.assertTrue(url is not None)
        os.unlink('nopw.bin')

        fid, secret = ffsend.parse_url(url)

        with self.assertRaises(FFSendError):
            ffsend.download(fid, secret, '.')

        ffsend.delete(fid, token)

        with self.assertRaises(FFSendError):
            ffsend.download(fid, secret, '.', 'password', url)

if __name__ == '__main__':
    unittest.main()
