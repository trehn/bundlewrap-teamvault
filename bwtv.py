from base64 import b64decode
try:
    from configparser import SafeConfigParser, NoSectionError, NoOptionError
except ImportError:  # Python 2
    from ConfigParser import SafeConfigParser, NoSectionError, NoOptionError
from hashlib import sha512
from os import environ
from os.path import expanduser

from bundlewrap.utils.text import yellow
from bundlewrap.utils.ui import io
from passlib.hash import apr_md5_crypt, sha512_crypt
from requests import get


class InsufficientPrivileges(Exception):
    pass


class MissingCredentials(Exception):
    pass


CONFIG_PATH = expanduser("~/.bw_teamvault_secrets.cfg")
DUMMY_MODE = environ.get("BW_TEAMVAULT_DUMMY_MODE", "0") == "1"

cache = {}
config = SafeConfigParser()
try:
    config.read([CONFIG_PATH])
except:
    io.stderr("{x} WARNING: Unable to read TeamVault config at {path}".format(
        path=CONFIG_PATH,
        x=yellow("!"),
    ))


class Fault(object):
    def __init__(self, secret_id, site="default"):
        self.cache_key = "{}:{}".format(site, secret_id)
        self.site = site
        self.secret_id = secret_id

    def __repr__(self):
        return "<TeamVault{} {}>".format(self.__class__.__name__, self.cache_key)

    def _fetch_secret(self):
        try:
            full_url = "{}/api/secrets/{}/".format(
                config.get(self.site, "url"),
                self.secret_id,
            )
            credentials = (
                config.get(self.site, "username"),
                config.get(self.site, "password"),
            )
        except (NoSectionError, NoOptionError):
            raise MissingCredentials(
                "Tried to get TeamVault secret with ID '{secret_id}' "
                "from site '{site}', but credentials missing in {path}".format(
                    path=CONFIG_PATH,
                    secret_id=self.secret_id,
                    site=self.site,
                ),
            )

        response = get(full_url, auth=credentials)
        if response.status_code != 200:
            raise InsufficientPrivileges(
                "TeamVault returned {status} for {url}".format(
                    status=response.status_code,
                    url=full_url,
                )
            )
        secret = response.json()

        response = get(secret['current_revision'] + "data", auth=credentials)
        if response.status_code != 200:
            raise InsufficientPrivileges(
                "TeamVault returned {status} for {url}".format(
                    status=response.status_code,
                    url=full_url,
                )
            )

        secret['data'] = response.json()
        return secret

    def _get_secret(self):
        if self.secret_id not in cache:
            cache[self.cache_key] = self._fetch_secret()
        return cache[self.cache_key]

    @property
    def is_available(self):
        if self.cache_key in cache:
            value = cache[self.cache_key]
            return value is not None
        else:
            try:
                cache[self.cache_key] = self._fetch_secret()
            except (InsufficientPrivileges, MissingCredentials):
                cache[self.cache_key] = None
                return False
            else:
                return True

    @property
    def secret(self):
        assert self.is_available
        return cache[self.cache_key]


class File(Fault):
    def __str__(self):
        if DUMMY_MODE:
            return "TEAMVAULT DUMMY CONTENT"
        else:
            return b64decode(self.secret['data']['file']).decode('utf-8')

    def raw(self):
        if DUMMY_MODE:
            return b"TEAMVAULT DUMMY CONTENT"
        else:
            return b64decode(self.secret['data']['file'])


class FileBase64(Fault):
    def __str__(self):
        if DUMMY_MODE:
            return "TEAMVAULT DUMMY CONTENT"
        else:
            return self.secret['data']['file']


class HtpasswdEntry(Fault):
    def __str__(self):
        if DUMMY_MODE:
            return "TEAMVAULT:DUMMYCONTENT"
        else:
            return "{}:{}".format(
                self.secret['username'],
                apr_md5_crypt.encrypt(
                    self.secret['data']['password'],
                    salt=sha512(self.secret_id.encode('utf-8')).hexdigest()[:8],
                ),
            )


class Password(Fault):
    def __str__(self):
        if DUMMY_MODE:
            return "TEAMVAULT_DUMMY_CONTENT"
        else:
            return self.secret['data']['password']


class PasswordCryptSHA512(Fault):
    def __str__(self):
        if DUMMY_MODE:
            return "TEAMVAULT_DUMMY_CONTENT"
        else:
            return sha512_crypt.encrypt(
                self.secret['data']['password'],
                salt=sha512(self.secret_id.encode('utf-8')).hexdigest()[:16],
                rounds=5000,
            )


class Username(Fault):
    def __str__(self):
        if DUMMY_MODE:
            return "TEAMVAULT_DUMMY_CONTENT"
        else:
            return self.secret['username']


class Format(object):
    def __init__(self, fault, format_string):
        self.fault = fault
        self.format_string = format_string

    def __str__(self):
        return self.format_string.format(str(self.fault))

    def __repr__(self):
        return self.format_string.format(repr(self.fault))
