import unittest
import ffsend
import tempfile
import random
import os
import shutil
import requests
import sys
import re
import pytest

@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    pytest_html = item.config.pluginmanager.getplugin('html')
    report = outcome.get_result()
    extra = getattr(report, 'extra', [])
    if report.when == 'call':
        # always add url to report
        extra.append(pytest_html.extras.url('lint.txt'))
        report.extra = extra

FFSendError = requests.HTTPError

class TestFFSend(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.data_tiny = os.urandom(random.getrandbits(4))
        self.password = ''.join(random.choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789')
                                for _ in range(random.randint(1, 16)))
        self.origdir = os.getcwd()
        self.service = os.environ['SERVICE'] if ('SERVICE' in os.environ) else 'https://send.firefox.com/'
        if re.match(r'.*/$', self.service) is None:
            self.service += '/'
        os.chdir(self.tmpdir)

    def tearDown(self):
        os.chdir(self.origdir)
        shutil.rmtree(self.tmpdir)

    def do_test(self, service, filename, data, password=None):
        with open(filename, 'wb') as f:
            f.write(data)

        url, token = ffsend.upload(service, filename, password=password)
        self.assertTrue(url is not None)
        os.unlink(filename)

        service, fid, secret = ffsend.parse_url(url)
        self.assertTrue(service is not None)
        self.assertTrue(secret is not None)

        metadata = ffsend.get_metadata(service, fid, secret, password, url)
        self.assertEqual(metadata['metadata']['name'], filename)
        self.assertEqual(metadata['metadata']['size'], len(data))

        ffsend.download(service, fid, secret, '.', password, url)
        with open(filename, 'rb') as f:
            self.assertEqual(data, f.read())

    # Basic tests
    def test_empty(self):
        self.do_test(self.service, 'empty.bin', b'')

    def test_tiny(self):
        self.do_test(self.service, 'tiny.bin', self.data_tiny)

    def test_small(self):
        self.do_test(self.service, 'small.bin', os.urandom(random.getrandbits(16)))

    def test_big(self):
        self.do_test(self.service, 'big.bin', os.urandom((1 << 20) + random.getrandbits(20)))

    # Basic tests with passwords
    def test_empty_pw(self):
        self.do_test(self.service, 'empty.bin', b'', self.password)

    def test_tiny_pw(self):
        self.do_test(self.service, 'tiny.bin', self.data_tiny, self.password)

    def test_small_pw(self):
        self.do_test(self.service, 'small.bin', os.urandom(random.getrandbits(16)), self.password)

    def test_big_pw(self):
        self.do_test(self.service, 'big.bin', os.urandom((1 << 20) + random.getrandbits(20)), self.password)

    # Test owner functionality
    def test_delete(self):
        with open('delete.bin', 'wb') as f:
            f.write(self.data_tiny)

        url, token = ffsend.upload(self.service, 'delete.bin')
        self.assertTrue(url is not None)
        os.unlink('delete.bin')

        service, fid, secret = ffsend.parse_url(url)
        ffsend.delete(service, fid, token)

        with self.assertRaises(FFSendError):
            ffsend.download(service, fid, secret, '.')

    def test_bad_delete(self):
        with open('delete.bin', 'wb') as f:
            f.write(self.data_tiny)

        url, token = ffsend.upload(self.service, 'delete.bin')
        self.assertTrue(url is not None)
        os.unlink('delete.bin')

        service, fid, secret = ffsend.parse_url(url)
        ffsend.download(service, fid, secret, '.')

        with self.assertRaises(FFSendError):
            ffsend.delete(service, fid, token)

    def test_delete_pw(self):
        with open('delete.bin', 'wb') as f:
            f.write(self.data_tiny)

        url, token = ffsend.upload(self.service, 'delete.bin', password='password')
        self.assertTrue(url is not None)
        os.unlink('delete.bin')

        service, fid, secret = ffsend.parse_url(url)
        ffsend.delete(service, fid, token)

        with self.assertRaises(FFSendError):
            ffsend.download(service, fid, secret, '.', 'password', url)

    def test_no_pw(self):
        with open('nopw.bin', 'wb') as f:
            f.write(self.data_tiny)

        url, token = ffsend.upload(self.service, 'nopw.bin', password='password')
        self.assertTrue(url is not None)
        os.unlink('nopw.bin')

        service, fid, secret = ffsend.parse_url(url)

        with self.assertRaises(FFSendError):
            ffsend.download(service, fid, secret, '.')

        ffsend.delete(service, fid, token)

        with self.assertRaises(FFSendError):
            ffsend.download(service, fid, secret, '.', 'password', url)

    @unittest.skip("Send limits anonymous users to only 1 download now")
    def test_set_dlimit(self):
        filename = 'dlimit.bin'
        with open(filename, 'wb') as f:
            f.write(self.data_tiny)

        url, token = ffsend.upload(self.service, filename)
        self.assertTrue(url is not None)
        os.unlink(filename)

        service, fid, secret = ffsend.parse_url(url)

        ffsend.set_params(service, fid, token, dlimit=2)

        for i in range(2):
            ffsend.download(service, fid, secret, '.')
            with open(filename, 'rb') as f:
                self.assertEqual(self.data_tiny, f.read())
            os.unlink(filename)

        with self.assertRaises(FFSendError):
            ffsend.download(service, fid, secret, '.')

    def test_main(self):
        ''' redirect stdout to a pipe in order to parse
        what comes from stdout to get url and token. '''
        stdout = sys.stdout
        ppr, ppw = os.pipe()
        sys.stdout = os.fdopen(ppw, 'w')
        console = os.fdopen(ppr, 'r')

        filename = 'tiny.bin'
        with open(filename, 'wb') as f:
            f.write(self.data_tiny)

        ffsend.main(['-s', self.service, filename])

        sys.stdout.close()

        ctxt = console.read()
        url = re.search('Your download link is (.*)', ctxt).group(1)
        token = re.search('Owner token is (.*)', ctxt).group(1)

        # restore stdout
        console.close()
        sys.stdout = stdout
        print(ctxt)
        self.assertTrue(url is not None)
        self.assertTrue(token is not None)

        service, fid, secret = ffsend.parse_url(url)

        ffsend.main(['-i', '-t', token, url])
        ffsend.main(['--delete', '-t', token, url])

        with self.assertRaises(FFSendError):
            ffsend.download(service, fid, secret, '.')


if __name__ == '__main__':
    unittest.main()
