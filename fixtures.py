import pexpect
import pytest
import sys
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


@pytest.fixture(scope="session")
def root_user():
    return user_factory("root")
