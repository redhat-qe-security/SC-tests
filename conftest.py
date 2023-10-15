import logging

from SCAutolib.utils import user_factory, ipa_factory, token_factory, \
    local_ca_factory
from fixtures import *
from pathlib import Path

log = logging.getLogger("PyTest")
log.setLevel(logging.DEBUG)
ipa_user = None
ipa_server = None
local_user = None
tokens = None


def load_tokens(user, token_list):
    log.info("Loading tokens")
    for index, token in enumerate(token_list):
         log.debug("Loading %s. token", index)
         setattr(user, f"card_{index}", token_factory(token, update_sssd = True))
         log.debug(f"Token %s is loaded", index)


def update_ca(user, token_list):
    log.info("Loading local CA")
    for index, token in enumerate(token_list):
        card_name = f"card_{index}"
        card = getattr(user, card_name, None)
        ca = local_ca_factory(ca_name=card.ca_name)
        ca.update_ca_db()
    log.debug("CA database is updated")


def pytest_configure(config):
    global ipa_user
    global ipa_server
    global local_user
    global tokens
    user_type = config.getoption("user_type")
    tokens = config.getoption("tokens")

    # workaround to set default token as parser.addoption defining tokens
    # is a list that needs to be empty by default
    if not tokens:
        tokens = ["virt-card-1"]

    if user_type in ["ipa", "all"]:
        log.debug("Loading IPA client")
        ipa_server = ipa_factory()
        log.debug("IPA client is loaded")
        log.debug("Loading IPA user")
        ipa_user = user_factory(
            config.getoption("ipa_username"),
            ipa_server=ipa_server)
        assert ipa_user.user_type == "ipa"
        log.debug("IPA user is loaded")
        load_tokens(ipa_user, tokens)
        ipa_user.card = ipa_user.card_0
        ipa_user.pin = ipa_user.card.pin
    if user_type in ["local", "all"]:
        log.debug("Loading local user")
        local_user = user_factory(config.getoption(
            "local_username"))
        assert local_user.user_type == "local"
        log.debug("Local user is loaded")
        load_tokens(local_user, tokens)
        # backwards compatibility fix. Older tests expected one virtual card
        # as attribute of user - i.e. user.card and approached card this way.
        # As of now we expect user can have multiple cards, they are marked
        # user.card_0, user.card_1, ... however, for backwards compatibility,
        # we need to provide user.card:
        local_user.card = local_user.card_0

        # pin used to be user attribute. as we can currently have multiple cards
        # pin was moved to card. For backwards compatibility:
        local_user.pin = local_user.card.pin

        update_ca(local_user, tokens)


def pytest_addoption(parser):
    """
    Specification of CLI options.
    """
    parser.addoption(
        "--ipa-username",
        action="store",
        default='ipa-user',
        help="Username of IPA user to be used in tests",
        dest="ipa_username"
    )
    parser.addoption(
        "--local-username",
        action="store",
        default='local-user',
        help="Username of local user to be used in tests",
        dest="local_username"
    )
    parser.addoption(
        "--with-user-type",
        action="store",
        default='local',
        dest="user_type",
        help="Type of user to be used in tests",
        choices=['local', 'ipa', 'all']
    )
    parser.addoption(
        "--with-tokens",
        action="append",
        default=[],
        dest="tokens",
        help="List of tokens to be prepared"
    )


def pytest_generate_tests(metafunc):
    """
    Injecting fixtures into tests.

    This function would set 'user' argument in test (if present) for users that
    we want to test.

    For example, if we want to execute the test only with local user, we
    need to se `--with-user-type local` in pytest command. Default name for
    local user is "local-user". If the system is configured to a user with
    different name, set this name with `--local-username NAME` option.
    Similar options are available for IPA user. If we want to test with both,
    use `--with-user-type all`. This would set 'user' argument to both local
    and IPA user using names specified by `--local-username` and
    `--ipa-username` (or default names if not specified).

    To avoid executing test that are not relevant for the user type (e.g. test
    that is relevant only for local user), this test has to specify explicitly
    user type by adding `local_user` argument instead of `user` argument.
    Similar is true for `ipa_user` argument.
    """
    user_type = metafunc.config.getoption("user_type")

    if 'user' in metafunc.fixturenames:
        users = []
        if user_type in ["local", "all"]:
            users.append(local_user)
        if user_type in ["ipa", "all"]:
            users.append(ipa_user)
        metafunc.parametrize("user", users)
    if 'ipa_user' in metafunc.fixturenames:
        metafunc.parametrize("ipa_user", [ipa_user])
    if 'local_user' in metafunc.fixturenames:
        metafunc.parametrize("local_user", [local_user])
    if "ipa_server" in metafunc.fixturenames:
        metafunc.parametrize("ipa_server", [ipa_server])
    if "tokens" in metafunc.fixturenames:
        metafunc.parametrize("tokens", [tokens])
