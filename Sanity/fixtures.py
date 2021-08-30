import pytest
from SCAutolib.src import read_config
from SCAutolib.src.authselect import Authselect
from SCAutolib.src.virt_card import VirtCard
from SCAutolib.src.utils import run_cmd, check_output


class User:
    def __init__(self):
        self.ROOT_PASSWD = read_config("root_passwd")
        self.USERNAME_LOCAL = read_config("local_user.name")
        self.PASSWD_LOCAL = read_config("local_user.passwd")
        self.PIN_LOCAL = read_config("local_user.pin")

    def su_login_local_with_sc(self):
        with Authselect(required=False):
            with VirtCard(self.USERNAME_LOCAL, insert=True):
                cmd = f'su - {self.USERNAME_LOCAL} -c "su - ' \
                      f'{self.USERNAME_LOCAL} -c whoami"'
                output = run_cmd(cmd, passwd=self.PIN_LOCAL, pin=True)
                check_output(output, expect=self.USERNAME_LOCAL)

    def su_login_local_with_passwd(self):
        with Authselect(required=False):
            with VirtCard(self.USERNAME_LOCAL, insert=True):
                cmd = f'su - {self.USERNAME_LOCAL} -c "su - ' \
                      f'{self.USERNAME_LOCAL} -c whoami"'
                output = run_cmd(cmd, passwd=self.PASSWD_LOCAL, pin=False)
                check_output(output, expect=self.USERNAME_LOCAL)


@pytest.fixture()
def user():
    return User()