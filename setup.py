import setuptools


DISTRIBUTION_NAME = "ffsend"
VERSION = "0.1.0"
DESCRIPTION = "A Firefox Send client."
STANDALONE_MODULES = ["ffsend"]
CONSOLE_SCRIPTS = ["ffsend = ffsend:cli"]
INSTALL_REQUIRES = ["clint", "pycryptodome", "requests"]

setuptools.setup(
    name=DISTRIBUTION_NAME,
    version=VERSION,
    description=DESCRIPTION,
    py_modules=STANDALONE_MODULES,
    install_requires=INSTALL_REQUIRES,
    entry_points={"console_scripts": CONSOLE_SCRIPTS},
)
