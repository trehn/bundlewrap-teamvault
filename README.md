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
pass_command = pass show teamvault
```

`pass_command` will be executed by bundlewrap-teamvault. It will then use
the first line of stdout as your teamvault password. This allows you to
store your password securely in your password manager, instead of keeping
it in plaintext in your home.

Please note that setting `password` will take preference. If both options
are set, `pass_command` will not be executed.

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
