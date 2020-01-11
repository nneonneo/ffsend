from setuptools import setup


with open('README.md') as f:
    long_description = f.read()

setup(
    name="ffsend",
    version="0.1.2",
    description="A Firefox Send client.",
    long_description=long_description,
    long_description_content_type='text/markdown',

    author = 'Robert Xiao',
    author_email = 'robert.bo.xiao@gmail.com',
    url = 'https://github.com/nneonneo/ffsend',
    license = 'MPL 2.0',
    classifiers = [
        "License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)",
        "Development Status :: 4 - Beta",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Topic :: Utilities",
        "Topic :: Communications :: File Sharing",
    ],

    py_modules=["ffsend"],
    install_requires=["clint", "pycryptodome", "requests"],
    entry_points={"console_scripts": ["ffsend = ffsend:main"]},
)
