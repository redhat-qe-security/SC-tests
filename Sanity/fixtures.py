import pytest
from SCAutolib.src import read_config
from SCAutolib.src.authselect import Authselect
from SCAutolib.src.virt_card import VirtCard
from SCAutolib.src.utils import (run_cmd, check_output, edit_config_,
                                 restart_service, backup_, restore_file_,
                                 show_file_diff)


class User:
    ROOT_PASSWD = read_config("root_passwd")
    USERNAME_LOCAL = None
    PASSWD_LOCAL = None
    PIN_LOCAL = None

    def su_login_local_with_sc(self):
        with Authselect(required=False):
            with VirtCard(self.USERNAME_LOCAL, insert=True):
                cmd = f'su - {self.USERNAME_LOCAL} -c "su - ' \
                      f'{self.USERNAME_LOCAL} -c whoami"'
                output = run_cmd(cmd, passwd=self.PIN_LOCAL, pin=True)
                check_output(output, expect=self.USERNAME_LOCAL,
                             zero_rc=True, check_rc=True)

    def su_login_local_with_passwd(self):
        with Authselect(required=False):
            with VirtCard(self.USERNAME_LOCAL, insert=True):
                cmd = f'su - {self.USERNAME_LOCAL} -c "su - ' \
                      f'{self.USERNAME_LOCAL} -c whoami"'
                output = run_cmd(cmd, passwd=self.PASSWD_LOCAL, pin=False)
                check_output(output, expect=self.USERNAME_LOCAL,
                             zero_rc=True, check_rc=True)


class LocalUser(User):
    def __init__(self):
        self.USERNAME_LOCAL = read_config("local_user.name")
        self.PASSWD_LOCAL = read_config("local_user.passwd")
        self.PIN_LOCAL = read_config("local_user.pin")


class IPAUser(User):
    def __init__(self):
        self.USERNAME = read_config("ipa_user.name")
        self.PASSWD = read_config("ipa_user.passwd")
        self.PIN = read_config("ipa_user.pin")


@pytest.fixture()
def edit_config(file_path, section, key, value, restore, restart):
    """Used for editing given configuration file. Arguments are based through
    the pytest.mark.parametrize decorator"""
    destination_path = backup_(file_path)

    edit_config_(file_path, section, key, value)
    for service in restart:
        restart_service(service)
    show_file_diff(file_path, destination_path)

    yield

    if restore:
        restore_file_(destination_path, file_path)
        for service in restart:
            restart_service(service)


def local_user():
    return LocalUser()


def ipa_user_():
    return IPAUser()


@pytest.fixture(name="user")
def user_indirect():
    """Returns an object of local user"""
    return local_user()


@pytest.fixture(name="ipa_user")
def ipa_user_indirect():
    """Returns an object of IPA user"""
    return ipa_user_()


@pytest.fixture()
def backup(file_path, restore, restart):
    assert type(file_path) == str
    assert type(restore) == bool
    assert (type(restart) == list) or (type(restart) == str)
    target = backup_(file_path)
    if type(restart) == str:
        restart = [restart]

    for service in restart:
        restart_service(service)

    yield

    if restore:
        restore_file_(target, file_path)
        for service in restart:
            restart_service(service)
