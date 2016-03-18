from base64 import b64decode
try:
    from configparser import SafeConfigParser, NoSectionError, NoOptionError
except ImportError:  # Python 2
    from ConfigParser import SafeConfigParser, NoSectionError, NoOptionError
from hashlib import sha512
from os import environ
from os.path import expanduser

from bundlewrap.exceptions import FaultUnavailable
from bundlewrap.utils import Fault
from bundlewrap.utils.text import yellow
from bundlewrap.utils.ui import io
from passlib.hash import apr_md5_crypt, sha512_crypt
from requests import get


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


def fault_callback(callback):
    def wrapped(secret_id, site="default"):
        return Fault(callback, secret_id=secret_id, site=site)
    return wrapped


def _fetch_secret(site, secret_id):
    try:
        return cache[site][secret_id]
    except KeyError:
        pass

    try:
        full_url = "{}/api/secrets/{}/".format(
            config.get(site, "url"),
            secret_id,
        )
        credentials = (
            config.get(site, "username"),
            config.get(site, "password"),
        )
    except (NoSectionError, NoOptionError):
        raise FaultUnavailable(
            "Tried to get TeamVault secret with ID '{secret_id}' "
            "from site '{site}', but credentials missing in {path}".format(
                path=CONFIG_PATH,
                secret_id=secret_id,
                site=site,
            ),
        )

    response = get(full_url, auth=credentials)
    if response.status_code != 200:
        raise FaultUnavailable(
            "TeamVault returned {status} for {url}".format(
                status=response.status_code,
                url=full_url,
            )
        )
    secret = response.json()

    response = get(secret['current_revision'] + "data", auth=credentials)
    if response.status_code != 200:
        raise FaultUnavailable(
            "TeamVault returned {status} for {url}".format(
                status=response.status_code,
                url=full_url,
            )
        )

    secret['data'] = response.json()

    cache.setdefault(site, {})[secret_id] = secret

    return secret


@fault_callback
def file(secret_id=None, site=None):
    if DUMMY_MODE:
        return b"TEAMVAULT DUMMY CONTENT"
    else:
        secret = _fetch_secret(site, secret_id)
        return b64decode(secret['data']['file'])
File = file


@fault_callback
def file_as_base64(secret_id=None, site=None):
    if DUMMY_MODE:
        return "TEAMVAULT DUMMY CONTENT"
    else:
        secret = _fetch_secret(site, secret_id)
        return secret['data']['file']
FileBase64 = file_as_base64


@fault_callback
def htpasswd_entry(secret_id=None, site=None):
    if DUMMY_MODE:
        return "TEAMVAULT:DUMMYCONTENT"
    else:
        secret = _fetch_secret(site, secret_id)
        return "{}:{}".format(
            secret['username'],
            apr_md5_crypt.encrypt(
                secret['data']['password'],
                salt=sha512(secret_id.encode('utf-8')).hexdigest()[:8],
            ),
        )
HtpasswdEntry = htpasswd_entry


@fault_callback
def password(secret_id=None, site=None):
    if DUMMY_MODE:
        return "TEAMVAULT_DUMMY_CONTENT"
    else:
        secret = _fetch_secret(site, secret_id)
        return secret['data']['password']
Password = password


@fault_callback
def password_crypt_sha512(secret_id=None, site=None):
    if DUMMY_MODE:
        return "TEAMVAULT_DUMMY_CONTENT"
    else:
        secret = _fetch_secret(site, secret_id)
        return sha512_crypt.encrypt(
            secret['data']['password'],
            salt=sha512(secret_id.encode('utf-8')).hexdigest()[:16],
            rounds=5000,
        )
PasswordCryptSHA512 = password_crypt_sha512


@fault_callback
def username(secret_id=None, site=None):
    if DUMMY_MODE:
        return "teamvault_dummy_content"
    else:
        secret = _fetch_secret(site, secret_id)
        return secret['username']
Username = username


def _format(fault=None, format_string=None):
    return format_string.format(fault.value)


def format(fault, format_string):
    return Fault(
        _format,
        fault=fault,
        format_string=format_string,
    )
Format = format
