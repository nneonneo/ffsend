Python client to https://send.firefox.com. Encrypts and decrypts on the fly to reduce memory usage.  
  
Note: As of July 17, 2020, Firefox's Send is currently offline due to some abusive activity, and can cause an error like `404 Client Error`.  

[![Lint and Test Status](https://github.com/nneonneo/ffsend/workflows/Lint%20and%20Test/badge.svg)](https://nneonneo.github.io/ffsend/report/)
[![View on PyPI](https://badge.fury.io/py/ffsend.svg)](https://pypi.org/project/ffsend/)

## Using

Install it:

```bash
pip install ffsend
```

Usage is really simple:

```bash
ffsend 'https://send.firefox.com/download/abcdef0123/#keykeykey' # download a file to the current directory
ffsend path/to/file # upload a file to Firefox Send
```

## Advanced usage

Several commands take a `-t`/`--token` parameter, which is the "Owner token" displayed after a successful upload. If you uploaded the file with your browser, the owner token will be in the browser's `localStorage`.

### Getting file information

To get basic information:

```bash
ffsend -i 'https://send.firefox.com/download/abcdef0123'
```

To get more information (including number of times downloaded):

```bash
ffsend -i -t TOKEN 'https://send.firefox.com/download/abcdef0123'
```

### Deleting a file

```bash
ffsend --delete -t TOKEN 'https://send.firefox.com/download/abcdef0123'
```

### Updating file settings

```bash
ffsend --set-dlimit N -t TOKEN 'https://send.firefox.com/download/abcdef0123'
```

## License

Code is copyright Robert Xiao (nneonneo@gmail.com), and is licensed under the Mozilla Public License 2.0.
