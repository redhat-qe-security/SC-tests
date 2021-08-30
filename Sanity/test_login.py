import pytest
from SCAutolib.src.authselect import Authselect
from SCAutolib.src.env import read_config
from SCAutolib.src.utils import run_cmd, check_output
from SCAutolib.src.virt_card import VirtCard
from fixtures import *


def test_su_login_with_sc(user):
    """Basic su login to the user with a smart card."""
    with Authselect(required=False):
        with VirtCard(user.USERNAME_LOCAL, insert=True):
            cmd = f'su - {user.USERNAME_LOCAL} -c "su - ' \
                  f'{user.USERNAME_LOCAL} -c whoami"'
            output = run_cmd(cmd, passwd=user.PIN_LOCAL, pin=True)
            check_output(output, expect=user.USERNAME_LOCAL)


def test_su_login_with_sc_wrong(user):
    """Basic su login to the user with a smart card."""
    with Authselect(required=False):
        with VirtCard(user.USERNAME_LOCAL, insert=True):
            cmd = f'su - {user.USERNAME_LOCAL} -c "su - {user.USERNAME_LOCAL}"'
            output = run_cmd(cmd, passwd="1264325", pin=True)
            check_output(output, expect=["su: Authentication failure"],
                         zero_rc=False, check_rc=True)


def test_gdm_login_sc_required(user):
    """GDM login to the user when smart card is enforcing. Point is check
    that GDM prompts to insert the smart card if it is not inserted
    """
    with Authselect(required=True):
        with VirtCard(user.USERNAME_LOCAL) as sc:
            cmd = f'sssctl user-checks -s gdm-smartcard {user.USERNAME_LOCAL} -a auth'
            shell = run_cmd(cmd, return_val="shell")
            shell.expect("Please insert smart card")
            sc.insert()
            shell.expect(f"PIN for {user.USERNAME_LOCAL}")
            shell.sendline(user.PIN_LOCAL)
            check_output(shell.read(), expect=["pam_authenticate.*Success"])


def test_su_login_without_sc(user):
    """SU login without smart card."""
    with Authselect():
        with VirtCard(user.USERNAME_LOCAL):
            cmd = f'su - {user.USERNAME_LOCAL} -c "su - {user.USERNAME_LOCAL} -c whoami"'
            output = run_cmd(cmd, pin=False, passwd=user.PASSWD_LOCAL)
            check_output(output, expect=[user.USERNAME_LOCAL])


def test_su_to_root(user):
    """Test for smart card login to the local user and the su - to the root.
    Test is executed under root, this why there is need to do twice login
    into the localuser"""
    with Authselect(lock_on_removal=True, mk_homedir=True):
        with VirtCard(user.USERNAME_LOCAL, insert=True) as sc:
            shell = run_cmd(f'bash -c "su - {user.USERNAME_LOCAL}"', return_val="shell")
            shell.sendline(f"su - {user.USERNAME_LOCAL}")
            shell.sendline(user.PIN_LOCAL)
            shell.sendline("whoami")
            shell.expect(user.USERNAME_LOCAL)
            shell.sendline('su - root -c "whoami"')
            shell.sendline(user.ROOT_PASSWD)
            shell.expect("root")
