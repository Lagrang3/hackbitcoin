# HackBitcoin

This is a python library, a set of exercises and code examples aimed
to master the dark arts of bitcoin programming.
It is mostly based on Jimmy Song's book "Programming Bitcoin", but also
I use Andreas Antonopoulos "Mastering Bitcoin", though often I refer to
the original BIPs.

# Getting started

I advise to set up a virtual environment
```
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

In order to make requests to a bitcoin client you should create in the working
directory a `bitcoinconf.json` file with the `rpcuser`, `rpcpassword` and
`rpcconnect` values. For example
```
{
	"rpcuser": "lagrange",
	"rpcpassword": "mypassword",
	"rpcconnect": "127.0.0.1:8332"
}
```

# Test

```
pytest
```
