from SCAutolib.src.authselect import Authselect
from SCAutolib.src.utils import run_cmd
from SCAutolib.src.virt_card import VirtCard
from fixtures import ipa_user_indirect
import pytest


def test_smart_card_login_enforcing(ipa_user):
    """Test kerberos user tries to logging to the system with smart card. Smart
    card is enforced."""
    with Authselect(lock_on_removal=True, mk_homedir=True, required=True):
        with VirtCard(ipa_user.USERNAME, insert=False) as sc:
            sc.remove()
            cmd = f"sssctl user-checks -s gdm-smartcard {ipa_user.USERNAME} -a auth"
            shell = run_cmd(cmd, return_val="shell")
            shell.expect("Please insert smart card", timeout=10)
            sc.insert()
            shell.expect(f"PIN for {ipa_user.USERNAME}:")
            shell.sendline(ipa_user.PIN)
            shell.expect(f"pam_authenticate for user \[{ipa_user.USERNAME}\]: Success")


def test_kerberos_change_passwd(ipa_user):
    """Kerberos user tries to change it kerberos password after user is logged in
     to the system with smart card"""
    try:
        with Authselect(lock_on_removal=True):
            with VirtCard(ipa_user.USERNAME, insert=False) as f:
                cmd = f"su {ipa_user.USERNAME}"
                shell = run_cmd(cmd, return_val="shell")

                f.insert()

                shell.sendline("passwd")
                i = shell.expect(f"Changing password for user {ipa_user.USERNAME}.", timeout=5)
                assert i == 0
                i = shell.expect("Current Password:", timeout=5)
                assert i == 0
                shell.sendline(ipa_user.PASSWD)

                i = shell.expect("New password:", timeout=5)
                assert i == 0

                shell.sendline("new-password-1")

                i = shell.expect('Retype new password:', timeout=5)
                assert i == 0

                shell.sendline("new-password-1")
                i = shell.expect("passwd: all authentication tokens updated successfully.", timeout=5)
                assert i == 0
    finally:
        shell = run_cmd(f"ipa passwd {ipa_user.USERNAME}", return_val="shell")
        i = shell.expect("New Password:", timeout=5)
        assert i == 0

        shell.sendline(ipa_user.PASSWD)
        i = shell.expect("Enter New Password again to verify:", timeout=5)
        assert i == 0

        shell.sendline(ipa_user.PASSWD)

        i = shell.expect(f'Changed password for "{ipa_user.USERNAME}', timeout=5)
        assert i == 0


def test_kerberos_login_to_root(ipa_user):
    """Kerberos user tries to login to root with root password when after
    user is logged in with smart card. Smart card is enforced."""
    with Authselect(lock_on_removal=True, mk_homedir=True, required=True):
        with VirtCard(ipa_user.USERNAME, insert=True):
            cmd = "su ipa-user-3 -c 'su ipa-user-3'"
            shell = run_cmd(cmd, return_val="shell")
            shell.expect(f"PIN for {ipa_user.USERNAME}", timeout=10)
            shell.sendline(ipa_user.PIN)
            shell.sendline("su - -c 'whoami'")
            shell.expect("Password")
            shell.sendline(ipa_user.ROOT_PASSWD)
            shell.expect("root")
