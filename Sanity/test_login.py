# author: Pavel Yadlouski <pyadlous@redhat.com>
import SCAutolib.src.authselect as authselect
from SCAutolib.src.utils import run_cmd, check_output
from SCAutolib.src.virt_card import VirtCard

from testBase import TestBase


class TestLogin(TestBase):

    def test_su_login_with_sc(self):
        """Basic su login to the user with a smart card."""
        with authselect.Authselect(required=False):
            with VirtCard(self.USERNAME_LOCAL, insert=True):
                cmd = f'su - {self.USERNAME_LOCAL} -c "su - ' \
                      f'{self.USERNAME_LOCAL} -c whoami"'
                output = run_cmd(cmd, passwd=self.PIN_LOCAL, pin=True)
                check_output(output, expect=self.USERNAME_LOCAL)

    def test_su_login_with_sc_wrong(self):
        """Basic su login to the user with a smart card."""
        with authselect.Authselect(required=False):
            with VirtCard(self.USERNAME_LOCAL, insert=True):
                cmd = f'su - {self.USERNAME_LOCAL} -c "su - {self.USERNAME_LOCAL}"'
                output = run_cmd(cmd, passwd="1264325", pin=True)
                check_output(output, expect=["su: Authentication failure"],
                             zero_rc=False, check_rc=True)

    def test_gdm_login_sc_required(self):
        """GDM login to the user when smart card is enforcing. Point is check
        that GDM prompts to insert the smart card if it is not inserted
        """
        with authselect.Authselect(required=True):
            with VirtCard(self.USERNAME_LOCAL) as sc:
                cmd = f'sssctl user-checks -s gdm-smartcard {self.USERNAME_LOCAL} -a auth'
                shell = run_cmd(cmd, return_val="shell")
                shell.expect("Please insert smart card")
                sc.insert()
                shell.expect(f"PIN for {self.USERNAME_LOCAL}")
                shell.sendline(self.PIN_LOCAL)
                check_output(shell.read(), expect=["pam_authenticate.*Success"])

    def test_su_login_without_sc(self):
        """SU login without smart card."""
        with authselect.Authselect():
            with VirtCard(self.USERNAME_LOCAL):
                cmd = f'su - {self.USERNAME_LOCAL} -c "su - {self.USERNAME_LOCAL} -c whoami"'
                output = run_cmd(cmd, pin=False, passwd=self.PASSWD_LOCAL)
                check_output(output, expect=[self.USERNAME_LOCAL])

    def test_su_to_root(self):
        """Test for smart card login to the local user and the su - to the root.
        Test is executed under root, this why there is need to do twice login
        into the localuser"""
        with authselect.Authselect(lock_on_removal=True, mk_homedir=True):
            with VirtCard(self.USERNAME_LOCAL, insert=True) as sc:
                shell = run_cmd(f'bash -c "su - {self.USERNAME_LOCAL}"', return_val="shell")
                shell.sendline(f"su - {self.USERNAME_LOCAL}")
                shell.sendline(self.PIN_LOCAL)
                shell.sendline("whoami")
                shell.expect(self.USERNAME_LOCAL)
                shell.sendline('su - root -c "whoami"')
                shell.sendline(self.ROOT_PASSWD)
                shell.expect("root")
