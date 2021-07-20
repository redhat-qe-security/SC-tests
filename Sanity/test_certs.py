# author: Pavel Yadlouski <pyadlous@redhat.com>
import avocado
import SCAutolib.src.utils as utils
from shutil import copy2
from os import remove
from testBase import TestBase


class TestCertificates(TestBase):

    @utils.backup("/etc/sssd/pki/sssd_auth_ca_db.pem", service="sssd", restore=True)
    def test_wrong_issuer_cert(self):
        """Test failed smart card login when root certificate has different
        issuer then certificate on the smart card."""
        cert, key = utils.generate_cert()
        copy2(cert, "/etc/sssd/pki/sssd_auth_ca_db.pem")
        utils.check_su_login_with_sc(username=self.USERNAME, pin=False, passwd=self.PASSWD)
        remove(cert)
        remove(key)
