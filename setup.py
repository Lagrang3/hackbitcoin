from setuptools import setup, find_packages

with open('readme.md') as f:
    readme = f.read()

with open('license.txt') as f:
    license = f.read()

setup(
    name = 'hackbitcoin',
    version = '0.1.0',
    description = 'Learning Bitcoin programming',
    long_description = readme,
    author = 'Lagrang3',
    author_email = 'lagrang3@protonmail.com',
    url = 'https://github.com/lagrang3/hackbitcoin',
    license = license,
    packages=find_packages(exclude=('tests','docs'))
)
