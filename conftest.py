from fixtures import *
from SCAutolib.utils import user_factory, ipa_factory
import logging

log = logging.getLogger("PyTest")
log.setLevel(logging.DEBUG)


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


def pytest_generate_tests(metafunc):
    """
    This function would set 'user' argument in test (if present) for users that
    we want to test.

    For example, if we want to execute the test only with local user, we
    need to se `--with-user-type local` in pytest command. Defualt name for
    local user is "local-user". If the system is configured to a user with
    different name, set this name with `--local-username NAME` option.
    Similar options are available for IPA user. If we want to test with both,
    use `--with-user-type all`. This would set 'user' argument to both local
    and IPA user using names specified by `--local-username` and `--ipa-username`
    (or default names if not specified).

    To avoid execuing test that are not relevant for the user type (e.g. test
    that is relevant only for local user), this test has to specify expicitly
    user type by adding `local_user` argmunet inseted of `user` argument.
    Similar is true for `ipa_user` argument.
    """
    user_type = metafunc.config.getoption("user_type")
    if user_type == "ipa":
        pytest.ipa_server = ipa_factory()

    if 'user' in metafunc.fixturenames:
        users = []
        if user_type in ["local", "all"]:
            u = user_factory(metafunc.config.getoption("local_username"))
            assert u.local
            users.append(u)

        if user_type in ["ipa", "all"]:
            u = user_factory(metafunc.config.getoption("ipa_username"), ipa_server=pytest.ipa_server)
            assert not u.local
            users.append(u)

        metafunc.parametrize("user", users)
    elif 'ipa_user' in metafunc.fixturenames:
        u = user_factory(metafunc.config.getoption("ipa_username"), ipa_server=pytest.ipa_server)
        assert not u.local
        metafunc.parametrize("ipa_user", [u])
    elif 'local_user' in metafunc.fixturenames:
        u = user_factory(metafunc.config.getoption("local_username"))
        assert u.local
        metafunc.parametrize("local_user", [u])
