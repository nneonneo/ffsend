Python client to https://send.firefox.com. Encrypts and decrypts on the fly to reduce memory usage.

## Using

Prerequisites:

    pip install clint pycryptodome requests requests_toolbelt

Usage is really simple:

    python ffsend.py 'https://send.firefox.com/download/abcdef0123/#keykeykey' # download a file to the current directory
    python ffsend.py path/to/file # upload a file to Firefox Send

You can also set a download count limit during upload:

    python ffsend.py --set-dlimit 20 path/to/file # upload a file to Firefox Send

As of writing (June 20, 2018), the maximum download limit is 20 on `send.firefox.com`.

## Advanced usage

Several commands take a `-t`/`--token` parameter, which is the "Owner token" displayed after a successful upload. If you uploaded the file with your browser, the owner token will be in the browser's `localStorage`.

### Getting file information

To get basic information:

    python ffsend.py -i 'https://send.firefox.com/download/abcdef0123'

To get more information (including number of times downloaded):

    python ffsend.py -i -t TOKEN 'https://send.firefox.com/download/abcdef0123'

### Deleting a file

    python ffsend.py --delete -t TOKEN 'https://send.firefox.com/download/abcdef0123'

### Updating file settings

    python ffsend.py --set-dlimit N -t TOKEN 'https://send.firefox.com/download/abcdef0123'

## License

Code is copyright Robert Xiao (nneonneo@gmail.com), and is licensed under the Mozilla Public License 2.0.
