# author: Pavel Yadlouski <pyadlous@redhat.com>
import SCAutolib.src.authselect as authselect
import SCAutolib.src.virt_card as virt_sc
from SCAutolib import log
from testBase import TestBase


class TestLogin(TestBase):

    def test_su_login_with_sc(self):
        """Basic su login to the user with a smart card."""

        with authselect.Authselect(required=False):
            with virt_sc.VirtCard(self.USERNAME_LOCAL, insert=True) as sc:
                sc.run_cmd(f'su - {self.USERNAME_LOCAL} -c "su - {self.USERNAME_LOCAL} -c whoami"',
                           expect=self.USERNAME_LOCAL, passwd=self.PIN_LOCAL, pin=True,
                           check_rc=True)

    def test_su_login_with_sc_wrong(self):
        """Basic su login to the user with a smart card."""
        with authselect.Authselect(required=False):
            with virt_sc.VirtCard(self.USERNAME_LOCAL, insert=True) as sc:
                sc.run_cmd(f'su - {self.USERNAME_LOCAL} -c "su - {self.USERNAME_LOCAL}"',
                           expect="su: Authentication failure", passwd="1264325", pin=True,
                           zero_rc=False, check_rc=True)

    def test_gdm_login_sc_required(self):
        """GDM login to the user when smart card is enforcing. Point is check
        that GDM prompts to insert the smart card if it is not inserted
        """
        with authselect.Authselect(required=True):
            with virt_sc.VirtCard(self.USERNAME_LOCAL) as sc:
                cmd = f'sssctl user-checks -s gdm-smartcard {self.USERNAME_LOCAL} -a auth'
                shell = sc.run_cmd(cmd, expect="")
                shell.expect("Please insert smart card")
                sc.insert()
                shell.expect(f"PIN for {self.USERNAME_LOCAL}")
                shell.sendline(self.PIN_LOCAL)
                shell.expect("pam_authenticate.*Success")

    def test_su_login_without_sc(self):
        """SU login without smart card."""
        with authselect.Authselect():
            with virt_sc.VirtCard(self.USERNAME_LOCAL) as sc:
                cmd = f'su - {self.USERNAME_LOCAL} -c "su - {self.USERNAME_LOCAL} -c whoami"'
                sc.run_cmd(cmd, self.USERNAME_LOCAL, pin=False, passwd=self.PASSWD_LOCAL)

    def test_su_to_root(self):
        """Test for smart card login to the local user and the su - to the root.
        Test is executed under root, this why there is need to do twice login
        into the localuser"""
        with authselect.Authselect(lock_on_removal=True, mk_homedir=True):
            with virt_sc.VirtCard(self.USERNAME_LOCAL, insert=True) as sc:
                shell = sc.run_cmd(f'bash -c "su - {self.USERNAME_LOCAL}"', expect="")
                shell.sendline(f"su - {self.USERNAME_LOCAL}")
                shell.sendline(self.PIN_LOCAL)
                shell.sendline("whoami")
                shell.expect(self.USERNAME_LOCAL)
                shell.sendline('su - root -c "whoami"')
                shell.sendline(self.ROOT_PASSWD)
                shell.expect("root")
