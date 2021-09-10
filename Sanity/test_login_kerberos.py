import pytest
from SCAutolib.src.authselect import Authselect
from SCAutolib.src.env import read_config
from SCAutolib.src.utils import run_cmd, check_output
from SCAutolib.src.virt_card import VirtCard
from fixtures import *


def test_kerberos_change_passwd(ipa_user):
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
