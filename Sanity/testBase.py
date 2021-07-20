# author: Pavel Yadlouski <pyadlous@redhat.com>
from avocado import Test


class TestBase(Test):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.log.debug("Preparing varialbes")
        self.ROOT_PASSWD = self.params.get("root_passwd", path="/run/")
        self.PIN = self.params.get("pin", path="/run/local_user/")
        self.PASSWD = self.params.get("passwd", path="/run/local_user/")
        self.USERNAME = self.params.get("name", path="/run/local_user/")
