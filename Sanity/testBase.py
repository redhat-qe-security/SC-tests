# author: Pavel Yadlouski <pyadlous@redhat.com>
from SCAutolib import log
from avocado import Test


class TestBase(Test):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        log.debug("Preparing test variables")
        self.ROOT_PASSWD = self.params.get("root_passwd", path="/")
        self.USERNAME_LOCAL = self.params.get("name", path="/local_user/")
        self.PASSWD_LOCAL = self.params.get("passwd", path="/local_user/")
        self.PIN_LOCAL = self.params.get("pin", path="/local_user/")
