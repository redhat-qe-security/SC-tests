# author: Pavel Yadlouski <pyadlous@redhat.com>

import pytest
import sys
from time import sleep
import pexpect
from SCAutolib.models.authselect import Authselect
from SCAutolib.utils import run
from conftest import log, local_user as local_user_conftest


def login_shell_factory(username):
    """Returns login shell for username."""
    shell = pexpect.spawn(f"login {username}",
                          ignore_sighup=True, encoding="utf-8")
    shell.logfile = sys.stdout
    sleep(3)
    return shell


@pytest.mark.parametrize("uri,auth_stat", [
    ("pkcs11:slot-id=0", False),
    ("pkcs11:slot-id=0", True),
    ("wrong-uri", False),
    ("wrong-uri", True)
])
def test_su_login_p11_uri_slot_description(user, uri, auth_stat, sssd):
    """ This is sanity test of a PKCS #11 Uniform Resource Identifier (URI)
    integration to sssd.conf file. p11_uri allows to select PKCS #11 objects
    stored in PKCS #11 tokens and slots i.e. it allows to restrict the selection
    of devices used for Smartcard authentication. This test verifies that
    selection/restriction of tokens based on p11_uri works.

    Setup
        1. Prepare system for simple case of Smart Card authentication:
        2. Add sssd.conf file
        3. Put CA cert to /etc/sssd/pki/sssd_auth_ca_db.pem
    Test steps
        4. Add p11_uri to [pam] section of sssd.conf
        5. select authselect profile `authselect select sssd with-smartcard ...`
        6. restart sssd
        7. Open GDM login screen
        8. Insert card into the reader
    Expected result:
        a. With correct uri present in sssd.conf SC login should be successful
           for both tested authselect profiles.
        b. When incorrect uri is set user is either prompted to enter password
           and authenticates successfully without SC (with smartcard profile) or
           authentication fails if SC was required (with-smartcard-required).
    """
    with sssd(section="pam", key="p11_uri", value=uri):
        run(["ls", "-l", "/etc/sssd/sssd.conf"])
        with open("/etc/sssd/sssd.conf", "r") as f:
            print(f.read())
        with Authselect(required=auth_stat), user.card(insert=True):
            login_shell = login_shell_factory(user.username)
            if uri == "pkcs11:slot-id=0":
                login_shell.expect([f"PIN for {user.username}:", pexpect.EOF])
                login_shell.sendline(user.pin)
                login_shell.expect([user.username])
                login_shell.sendline("exit")
                login_shell.close()
            elif uri == "wrong-uri" and not auth_stat:
                login_shell.expect_exact(["Password:", pexpect.EOF])
                login_shell.sendline(user.password)
                login_shell.expect([user.username])
                login_shell.sendline("exit")
                login_shell.close()
            else:
                login_shell.expect("Please insert smart card")
                login_shell.sendline()
                login_shell.expect("Login incorrect")
                login_shell.sendline("exit")
                login_shell.close()


@pytest.mark.parametrize("uri,auth_stat", [
    ("pkcs11:slot-id=0", False),
    ("pkcs11:slot-id=0", True)
])
def test_su_login_p11_uri_user_mismatch(user, uri, auth_stat, sssd):
    """ This is sanity test of a PKCS #11 Uniform Resource Identifier (URI)
    integration to sssd.conf file. This test verifies that matchrule present in
    sssd.conf is respected when p11_uri (specifying token or object) is present.

    Setup
        1. Prepare system for simple case of Smart Card authentication:
        2. Add sssd.conf file
        3. Put CA cert to /etc/sssd/pki/sssd_auth_ca_db.pem
        4. Add p11_uri to [pam] section of sssd.conf
        5. Modify subject of matchrule of sssd.conf to contain incorrect value
    Test steps
        6. select authselect profile `authselect select sssd with-smartcard ...`
        7. restart sssd
        8. Open GDM login screen
        9. Insert card into the reader
    Expected result:
        User is either prompted to enter password and authenticates succesfully
        without SC or authentication fails depending on selected authselect
        profile.
    """
    with sssd(section="pam", key="p11_uri", value=uri) as sssd_conf:
        run(["ls", "-l", "/etc/sssd/sssd.conf"])
        # update sssd.conf to contain mismatch in matchrule
        sssd_conf(section=f"certmap/shadowutils/{user.username}",
                  key="matchrule",
                  value="<SUBJECT>.*CN=testuser.*")
        with open("/etc/sssd/sssd.conf", "r") as f:
            print(f.read())
        with Authselect(required=auth_stat), user.card(insert=True):
            login_shell = login_shell_factory(user.username)
            if not auth_stat:
                login_shell.expect_exact(["Password:", pexpect.EOF])
                login_shell.sendline(user.password)
                login_shell.expect([user.username])
                login_shell.sendline("exit")
                login_shell.close()
            else:
                login_shell.expect("Please insert smart card")
                login_shell.sendline()
                login_shell.expect_exact(
                    "Please (re)insert (different) Smartcard")
                login_shell.sendline()
                login_shell.expect("Login incorrect")
                login_shell.sendline("exit")
                login_shell.close()


def test_matchrule_defined_for_other_user(local_user, sssd, user_shell):
    """Test smart card login fail when sssd.conf do not contain
    [certmap/shadowutils/USER] section for the user from the SC. Instead,
    section for other ([certmap/shadowutils/WRONG_USER]) user is present"""
    # change section of sssd.conf to get [certmap/shadowutils/testuser]
    with sssd(section=f"certmap/shadowutils/{local_user.username}",
              key="matchrule",
              value="<SUBJECT>.*CN=testuser.*") as sssd_file:
        # FIXME: this section should be replaced with library call for removing
        #  the section as soon as this functionality is implemented
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
