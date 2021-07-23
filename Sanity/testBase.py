# author: Pavel Yadlouski <pyadlous@redhat.com>
from avocado import Test
from SCAutolib import log


class TestBase(Test):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        log.debug("Preparing varialbes")
        self.ROOT_PASSWD = self.params.get("root_passwd", path="/run/")
        self.users = self.params.get("users", path="/run/")
        log.debug(self.users)
        self.PIN = "123456"
        self.PASSWD = "654321"
        self.USERNAME = "local-user"
        self.WRONG_PASSWD = "q5435"
