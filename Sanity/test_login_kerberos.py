import sys

import pexpect
from SCAutolib.src.authselect import Authselect
from SCAutolib.src.utils import run_cmd, check_output
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
            shell.expect(rf"pam_authenticate for user \[{ipa_user.USERNAME}\]: Success")


@pytest.mark.skip(reason="Need fix due to specific password changing with IPA server")
def test_kerberos_change_passwd(ipa_user):
    """Kerberos user tries to change it kerberos password after user is logged in
     to the system with smart card"""
    # FIXME: test fails due to IPA password policies, so it is not stable
    with Authselect(lock_on_removal=True):
        with VirtCard(ipa_user.USERNAME, insert=True) as f:
            cmd = f"su {ipa_user.USERNAME} -c 'passwd'"
            out = run_cmd(cmd)
            check_output(out, [f"Changing password for user {ipa_user.USERNAME}."], check_rc=False)


def test_kerberos_login_to_root(ipa_user):
    """Kerberos user tries to login to root with root password when after
    user is logged in with smart card. Smart card is enforced."""
    with Authselect(lock_on_removal=True, mk_homedir=True, required=True):
        with VirtCard(ipa_user.USERNAME, insert=True):
            cmd = f"su {ipa_user.USERNAME} -c 'su {ipa_user.USERNAME}'"
            shell = run_cmd(cmd, return_val="shell")
            shell.expect(f"PIN for {ipa_user.USERNAME}", timeout=10)
            shell.sendline(ipa_user.PIN)
            shell.sendline("su - -c 'whoami'")
            shell.expect("Password")
            shell.sendline(ipa_user.ROOT_PASSWD)
            shell.expect("root")


def test_kerberos_user_sudo_wrong_password(ipa_user):
    """Kerberos user tries to use sudo to access some application and mistype
    the password. No need of smartcard."""

    with Authselect(required=True, lock_on_removal=True):
        cmd = f"su - {ipa_user.USERNAME} -c 'sudo -S ls /'"
        shell = pexpect.spawn(cmd, encoding='utf-8', logfile=sys.stdout)
        shell.expect(rf"\[sudo\] password for {ipa_user.USERNAME}:")
        shell.sendline("098765432")
        shell.expect("Sorry, try again.")
