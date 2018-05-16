Pull secrets from [TeamVault](https://github.com/trehn/teamvault) into your [BundleWrap](http://bundlewrap.org) repo.

# Installation

	pip install bundlewrap-teamvault

# Setup

Add this to your `~/.bw_teamvault_secrets.cfg`:

```
[foocorp]
url = https://teamvault.example.com
username = jdoe
password = potato
```

# Usage

Use in your `nodes.py` like this (replace ABCDEF with the hash id from the TeamVault URL of the secret you want):

```
import bwtv as teamvault

nodes = {
    "node1": {
        'metadata': {
            'secret': teamvault.password("ABCDEF", site="foocorp"),
        },
    },
}
```

Note: This will insert a proxy object into your metadata, the actual secret is not retrieved until you convert it to a string (e.g. by inserting it in a template or calling `str()` explicitly).

---

© 2016-2018 [Torsten Rehn](mailto:torsten@rehn.email)
