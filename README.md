Python client to https://send.firefox.com. Encrypts and decrypts on the fly to reduce memory usage.

[![Lint and Test Status](https://github.com/nneonneo/ffsend/workflows/Lint%20and%20Test/badge.svg)](https://nneonneo.github.io/ffsend/report/)
[![View on PyPI](https://badge.fury.io/py/ffsend.svg)](https://pypi.org/project/ffsend/)

## Using

Prerequisites:

```bash
pip install clint pycryptodome requests
```

Usage is really simple:

```bash
python ffsend.py 'https://send.firefox.com/download/abcdef0123/#keykeykey' # download a file to the current directory
python ffsend.py path/to/file # upload a file to Firefox Send
```

## Advanced usage

Several commands take a `-t`/`--token` parameter, which is the "Owner token" displayed after a successful upload. If you uploaded the file with your browser, the owner token will be in the browser's `localStorage`.

### Getting file information

To get basic information:

```bash
python ffsend.py -i 'https://send.firefox.com/download/abcdef0123'
```

To get more information (including number of times downloaded):

```bash
python ffsend.py -i -t TOKEN 'https://send.firefox.com/download/abcdef0123'
```

### Deleting a file

```bash
python ffsend.py --delete -t TOKEN 'https://send.firefox.com/download/abcdef0123'
```

### Updating file settings

```bash
python ffsend.py --set-dlimit N -t TOKEN 'https://send.firefox.com/download/abcdef0123'
```

## License

Code is copyright Robert Xiao (nneonneo@gmail.com), and is licensed under the Mozilla Public License 2.0.
