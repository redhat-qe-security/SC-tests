# author: Pavel Yadlouski <pyadlous@redhat.com>
import SCAutolib.src.utils as utils
from testBase import TestBase


class TestSssdConf(TestBase):

    @utils.edit_config("sssd", "p11_uri = pkcs11:slot-description=Virtual%20PCD%2000%2000", "pam")
    def test_su_login_p11_uri_slot_description(self):
        """Test login with PIN to the system with p11_uri specified on specific
        slot in sssd.conf."""
        utils.check_su_login_with_sc(passwd=self.PIN)

    @utils.edit_config("sssd", "p11_uri = pkcs11:slot-description=Virtual%20PCD%2000%2001", "pam")
    def test_su_login_p11_uri_wrong_slot_description(self):
        """Test login with password to the system with wrong p11_uri with wrong
        slot description in sssd.conf."""
        utils.check_su_login_with_sc(pin=False, passwd=self.PASSWD)

    def test_user_mismatch(self):
        """Test smart card login fail when sssd.conf do not contain user from
        the smart card (wrong user in matchrule)"""
        @utils.edit_config("sssd", "testuser", holder=self.USERNAME, section=False)
        def test_case():
            utils.check_su_login_with_sc(pin=False, passwd=self.PASSWD)
        test_case()

    def test_wrong_subject_in_matchrule(self):
        """Test smart card login fail when sssd.conf contain wrong subject in
        the matchrule."""
        @utils.edit_config(service="sssd", string=f"UID={self.USERNAME}", holder=f"CN={self.USERNAME}", section=False)
        def test_case():
            utils.check_su_login_with_sc(pin=False, passwd=self.PASSWD)
        test_case()
