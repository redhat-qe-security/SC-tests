import sys

import pexpect
import pytest
from SCAutolib import LIB_DUMP_USERS, LIB_DUMP_CARDS
from SCAutolib.models.card import Card
from SCAutolib.models.user import BaseUser


@pytest.fixture(scope="session")
def user(name):
    """
    Fixture loads the user and the card (if exists) from the JSON files.
    :param name: name of the user from config file provided to setup phase.
    :return: User object
    """
    user_file = LIB_DUMP_USERS.joinpath(f"{name}.json")
    user_card_file = LIB_DUMP_CARDS.joinpath(f"card-{name}.json")
    user = None
    if user_file.exists():
        user = BaseUser.load(user_file)
    if type(user) == tuple:
        card_file = user[1]
        user = user[0]
        user.card = Card.load(card_file, user=user)
    return user


@pytest.fixture(scope="function")
def user_shell():
    """Creates shell with some local user as a starting point for test."""
    shell = pexpect.spawn("/usr/bin/sh -c 'su base-user'", encoding="utf-8")
    shell.logfile = sys.stdout
    return shell
