# author: Pavel Yadlouski <pyadlous@redhat.com>
from SCAutolib import log
from SCAutolib.src.env import read_config
from avocado import Test


class TestBase(Test):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        log.debug("Preparing test variables")
        self.ROOT_PASSWD = read_config("root_password")
        self.USERNAME_LOCAL = read_config("local_user.name")
        self.PASSWD_LOCAL = read_config("local_user.passwd")
        self.PIN_LOCAL = read_config("local_user.pin")
