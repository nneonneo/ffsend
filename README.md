Python client to https://send.firefox.com. Encrypts and decrypts on the fly to reduce memory usage.

## Using

Prerequisites:

    pip install clint pycryptodome requests requests_toolbelt

Usage is really simple:

    python ffsend.py 'https://send.firefox.com/download/abcdef0123/#keykeykey' # download a file to the current directory
    python ffsend.py path/to/file # upload a file to Firefox Send

## License

Code is copyright Robert Xiao (nneonneo@gmail.com), and is licensed under the Mozilla Public License 2.0.
