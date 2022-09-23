# author: Pavel Yadlouski <pyadlous@redhat.com>

import pytest

from SCAutolib.models.authselect import Authselect
from SCAutolib.utils import run
from conftest import log, local_user as local_user_conftest


@pytest.mark.parametrize("uri", ["pkcs11:slot-id=0", "wrong-uri"])
def test_su_login_p11_uri_slot_description(local_user, uri, sssd, user_shell):
    """Test login with PIN to the system with p11_uri specified on specific
    slot in sssd.conf.

    Expected result:
        - when correct uri is set, user is prompted to insert the PIN
        - when incorrect uri is set, user is not prompted to insert the password
    """
    with sssd(section="pam", key="p11_uri",
              value=uri):
        run(["ls", "-l", "/etc/sssd/sssd.conf"])
        with open("/etc/sssd/sssd.conf", "r") as f:
            print(f.read())

        with Authselect(required=False), local_user.card(insert=True):
            cmd = f"su {local_user.username} -c whoami"
            user_shell.sendline(cmd)
            if uri == "wrong-uri":
                user_shell.expect_exact("Password:")
                user_shell.sendline(local_user.password)
            else:
                user_shell.expect(f"PIN for {local_user.username}")
                user_shell.sendline(local_user.pin)
            index = user_shell.expect([local_user.username, "su: Authentication failure"])
            if index == 1:
                log.error("User was not able to login")
                pytest.fail("Login is not sucessfull")


def test_matchrule_defined_for_other_user(local_user, sssd, user_shell):
    """Test smart card login fail when sssd.conf do not contain
    [certmap/shadowutils/USER] section for the user from the SC. Instead,
    section for other ([certmap/shadowutils/WRONG_USER]) user is present"""
    # change section of sssd.conf to get [certmap/shadowutils/testuser]
    with sssd(section=f"certmap/shadowutils/{local_user.username}",
              key="matchrule",
              value="<SUBJECT>.*CN=testuser.*") as sssd_file:
        # FIXME: this section should be replaced with library call for removing
        #  the section as sson as this functionality is implemented
        with sssd_file.path.open("r+") as sources:
            sourcesdata = sources.read()
            sourcesdata = sourcesdata.replace(
                f'[certmap/shadowutils/{local_user.username}]',
                '[certmap/shadowutils/testuser]')
            sources.write(sourcesdata)
        run(["systemctl", "restart", "sssd"])

        with Authselect(required=False), local_user.card(insert=True):
            cmd = f"su {local_user.username} -c whoami"
            user_shell.sendline(cmd)
            user_shell.expect_exact("Password:")
            user_shell.sendline(local_user.password)
            user_shell.expect(local_user.username)


@pytest.mark.parametrize("rule", ["<SUBJECT>.*CN=testuser.*", f"<SUBJECT>.*UID={local_user_conftest.username}.*"])
def test_user_mismatch(local_user, sssd, user_shell, rule):
    """Test smart card login fail when sssd.conf do not contain user from
    the smart card (wrong user in matchrule)"""
    with sssd(section=f"certmap/shadowutils/{local_user.username}",
              key="matchrule",
              value=rule):
        with Authselect(required=False), local_user.card(insert=True):
            cmd = f"su {local_user.username} -c whoami"
            user_shell.sendline(cmd)
            user_shell.expect_exact("Password:")
            user_shell.sendline(local_user.password)
            user_shell.expect(local_user.username)
