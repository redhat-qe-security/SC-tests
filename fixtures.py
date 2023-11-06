import pexpect
import pytest
import sys
import logging

from SCAutolib import run
from SCAutolib.models.file import SSSDConf
from SCAutolib.utils import user_factory


@pytest.fixture(scope="function")
def user_shell():
    """Creates shell with some local user as a starting point for test."""
    shell = pexpect.spawn("/usr/bin/sh -c 'su base-user'", encoding="utf-8")
    shell.logfile = sys.stdout
    return shell


@pytest.fixture(scope="function")
def root_shell():
    """Creates shell with root user as a starting point for test."""
    shell = pexpect.spawn("/usr/bin/sh -c 'su'", encoding="utf-8")
    shell.logfile = sys.stdout
    return shell


@pytest.fixture(scope="function")
def allow_sudo_commands(ipa_user):
    """
    Modifying the IPA server's sudo rules to allow the test user to
    run sudo commands and restore the original state afterward.
    """
    logger = logging.getLogger()

    run('ipa sudorule-add allow_sudo --hostcat=all --runasusercat=all '
        '--runasgroupcat=all --cmdcat=all'.split())
    run(f'ipa sudorule-add-user allow_sudo --user {ipa_user.username}'.split())
    run("systemctl restart sssd".split(), sleep=5)
    logger.debug("Checking that the sudo rule has been added (following command should succeed)")
    run('ipa sudorule-show allow_sudo'.split())
    yield   # running the test's code
    run('ipa sudorule-del allow_sudo'.split())
    run("systemctl restart sssd".split(), sleep=5)
    logger.debug("Checking that the sudo rule has been removed "
                 "(following command should exit with status 2)")
    run('ipa sudorule-show allow_sudo'.split(), return_code=[2])


@pytest.fixture(scope="session")
def root_user():
    return user_factory("root")


@pytest.fixture(scope="session")
def base_user():
    return user_factory("base-user")


@pytest.fixture(scope="session")
def sssd():
    return SSSDConf()
