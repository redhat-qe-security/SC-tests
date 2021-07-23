# author: Pavel Yadlouski <pyadlous@redhat.com>
import SCAutolib.src.virt_card as virt_sc
import SCAutolib.src.authselect as authselect
import SCAutolib.src.utils as utils
from testBase import TestBase


class TestLogin(TestBase):

    def test_su_login_with_sc(self):
        """Basic su login to the user with a smart card."""
        with authselect.Authselect(required=False):
            with virt_sc.VirtCard(self.USERNAME) as sc:
                sc.run_cmd(f'su - {self.USERNAME} -c "su - {self.USERNAME} -c whoami"',
                           expect=self.USERNAME, passwd="123456", pin=True)

    def test_su_login_with_sc_wrong(self):
        """Basic su login to the user with a smart card."""
        with authselect.Authselect(required=False):
            with virt_sc.VirtCard(self.USERNAME) as sc:
                sc.run_cmd(f'su - {self.USERNAME} -c "su - {self.USERNAME} -c whoami"',
                           expect="su: Authentication failer", passwd="9876543", pin=True)

    def test_gdm_login_sc_required(self):
        """GDM login to the user when smart card is enforcing."""
        with authselect.Authselect(required=True):
            with virt_sc.VirtCard(self.USERNAME) as sc:
                inner = f'sssctl user-checks -s gdm-smartcard {self.USERNAME} -a auth'
                cmd = f'bash -c "{inner}"'
                shell = sc.run_cmd(cmd, expect="")
                shell.expect("Please insert smart card")
                sc.insert()
                shell.expect(f"PIN for {self.USERNAME}")
                shell.sendline(self.PIN)
                shell.expect("pam_authenticate.*Success")

    def test_su_login_without_sc(self):
        """SU login without smart card."""
        with authselect.Authselect():
            with virt_sc.VirtCard(self.USERNAME) as sc:
                cmd = f'su - {self.USERNAME} -c "su - {self.USERNAME} -c whoami"'
                sc.run_cmd(cmd, self.USERNAME, pin=False, passwd=self.PASSWD)

    def test_su_to_root(self):
        """Test for smart card login to the local user and the su - to the root.
        Test is executed under root, this why there is need to do twice login
        into the localuser"""
        with authselect.Authselect(lock_on_removal=True, mk_homedir=True):
            with virt_sc.VirtCard(self.USERNAME, insert=True) as sc:
                shell = sc.run_cmd(f'bash -c "su - {self.USERNAME}"', expect="")
                shell.sendline(f"su - {self.USERNAME}")
                shell.sendline(self.PIN)
                shell.sendline("whoami")
                shell.expect(self.USERNAME)
                shell.sendline('su - root -c "whoami"')
                shell.sendline(self.ROOT_PASSWD)
                shell.expect("root")
