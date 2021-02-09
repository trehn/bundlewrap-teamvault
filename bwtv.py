from base64 import b64decode
from configparser import ConfigParser, NoSectionError, NoOptionError
from hashlib import sha512
from os import environ, getpid
from os.path import expanduser
from subprocess import check_output, CalledProcessError

from bundlewrap.exceptions import FaultUnavailable
from bundlewrap.utils import Fault
from bundlewrap.utils.text import bold, mark_for_translation as _, yellow
from bundlewrap.utils.ui import io
from passlib.hash import apr_md5_crypt, sha512_crypt
from requests import Session


CONFIG_PATH = expanduser(environ.get("BW_TEAMVAULT_SECRETS_FILE", "~/.bw_teamvault_secrets.cfg"))
DUMMY_MODE = environ.get("BW_TEAMVAULT_DUMMY_MODE", "0") == "1"

cache = {}
config = ConfigParser()
try:
    config.read([CONFIG_PATH])
except:
    io.stderr("{x} WARNING: Unable to read TeamVault config at {path}".format(
        path=CONFIG_PATH,
        x=yellow("!"),
    ))
sessions = {}

for site_name, site_config in config.items():
    if (
        ('password' not in site_config or not site_config['password'])
        and 'pass_command' in site_config
    ):
        try:
            config[site_name]['password'] = check_output(
                site_config['pass_command'],
                shell=True
            ).decode('UTF-8').splitlines()[0].strip()
        except (FileNotFoundError, CalledProcessError, IndexError) as e:
            io.stderr("{x} TeamVault pass_command for site {site} failed: {e}".format(
                x=yellow('!'),
                site=site_name,
                e=repr(e)
            ))


def _fetch_secret(site, secret_id):
    try:
        return cache[site][secret_id]
    except KeyError:
        pass

    session = sessions.setdefault(getpid(), Session())

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

    with io.job(_("{tv}  fetching {secret}").format(tv=bold("TeamVault"), secret=secret_id)):
        response = session.get(full_url, auth=credentials)
    if response.status_code != 200:
        raise FaultUnavailable(
            "TeamVault returned {status} for {url}".format(
                status=response.status_code,
                url=full_url,
            )
        )
    secret = response.json()

    response = session.get(secret['current_revision'] + "data", auth=credentials)
    if response.status_code != 200:
        raise FaultUnavailable(
            "TeamVault returned {status} for {url}".format(
                status=response.status_code,
                url=secret['current_revision'] + "data",
            )
        )

    secret['data'] = response.json()

    cache.setdefault(site, {})[secret_id] = secret

    return secret


def _file(secret_id=None, site=None):
    if DUMMY_MODE:
        return "TEAMVAULT DUMMY CONTENT"
    else:
        secret = _fetch_secret(site, secret_id)
        return b64decode(secret['data']['file']).decode('utf-8')


def file(secret_id, site="default"):
    return Fault("bwtv file", _file, secret_id=secret_id, site=site)


def _file_as_base64(secret_id=None, site=None):
    if DUMMY_MODE:
        return "TEAMVAULT DUMMY CONTENT"
    else:
        secret = _fetch_secret(site, secret_id)
        return secret['data']['file']


def file_as_base64(secret_id, site="default"):
    return Fault(
        "bwtv file_as_base64",
        _file_as_base64,
        secret_id=secret_id,
        site=site,
    )


def _htpasswd_entry(secret_id=None, site=None):
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


def htpasswd_entry(secret_id, site="default"):
    return Fault(
        "bwtv htpasswd_entry",
        _htpasswd_entry,
        secret_id=secret_id,
        site=site,
    )


def _password(secret_id=None, site=None):
    if DUMMY_MODE:
        return "TEAMVAULT_DUMMY_CONTENT"
    else:
        secret = _fetch_secret(site, secret_id)
        return secret['data']['password']


def password(secret_id, site="default"):
    return Fault("bwtv password", _password, secret_id=secret_id, site=site)


def _password_crypt_sha512(secret_id=None, site=None):
    if DUMMY_MODE:
        return "TEAMVAULT_DUMMY_CONTENT"
    else:
        secret = _fetch_secret(site, secret_id)
        return sha512_crypt.encrypt(
            secret['data']['password'],
            salt=sha512(secret_id.encode('utf-8')).hexdigest()[:16],
            rounds=5000,
        )


def password_crypt_sha512(secret_id, site="default"):
    return Fault(
        "bwtv password_crypt_sha512",
        _password_crypt_sha512,
        secret_id=secret_id,
        site=site,
    )


def _username(secret_id=None, site=None):
    if DUMMY_MODE:
        return "teamvault_dummy_content"
    else:
        secret = _fetch_secret(site, secret_id)
        return secret['username']


def username(secret_id, site="default"):
    return Fault("bwtv username", _username, secret_id=secret_id, site=site)


def _format(fault=None, format_string=None):
    return format_string.format(fault.value)


def format(fault, format_string):
    return Fault(
        "bwtv format",
        _format,
        fault=fault,
        format_string=format_string,
    )
