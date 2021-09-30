import sys

import pexpect
from SCAutolib.src.authselect import Authselect
from SCAutolib.src.utils import run_cmd, check_output
from SCAutolib.src.virt_card import VirtCard
from fixtures import ipa_user_indirect, user_shell
import pytest

"""General setup for this set of tests:
1. Setup IPA client and configure smartcard login for IPA
    - Smartcard login for IPA user is configured with script generated
      by IPA server (run 'ipa-advice config-client-for-smart-card-auth'
      to see the script). Script requires CA certificate from IPA server
      (by default stored in /etc/ipa/ca.crt after IPA client is
      installed) as an argument
2. Crete user private key, create CSR with created private key and
   request the certificate from IPA server
3. Create virtual smart card with certificate obtained from the IPA server

If not specified, use this setup by default.

Note: for virtual smart card 'insert the card' means to start systemd service
that represents the card.

"""


def test_smart_card_gdm_login_enforcing(ipa_user):
    """Test kerberos user tries to logging to the GDM with smart card. Smart
    card is enforced.

    Setup
        1. General setup
        2. Setup authselect: authselect select sssd with-smartcard with-smartcard-required
        3. Try to run 'sssctl user-checks -s gdm-smartcard kerberos_username -a auth'

    Expected result
        - User is asked to insert the smartcard
        - User inserts the smartcard
        - User is asked to insert smartcard PIN
        - User inserts correct smartcard PIN
        - Authentication is succeed.
    """
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
    """Kerberos user tries to change it kerberos password after user is logged
    in to the system with smartcard

    Setup
        1. General setup
        2. Setup authselect: authselect select sssd with-smartcard
        3. Switch to kerberos user (su kerberos_username)
        4. Insert the card
        5. Try to change the password by 'passwd'

    Expected result
        - Message about changing the password is written to the console
     """
    # FIXME: test fails due to IPA password policies, so it is not stable
    with Authselect():
        with VirtCard(ipa_user.USERNAME, insert=True) as f:
            cmd = f"su {ipa_user.USERNAME} -c 'passwd'"
            out = run_cmd(cmd)
            check_output(out, [f"Changing password for user {ipa_user.USERNAME}."], check_rc=False)


def test_kerberos_login_to_root(ipa_user):
    """Kerberos user tries to switch to the root user with root password after
    kerberos user is logged in with smart card. Smart card is required.

    Setup
        1. General setup
        2. Setup authselect: authselect select sssd with-smartcard with-smartcard-required
        3. Insert the card
        4. Switch to kerberos user (su kerberos_username)
        5. System asks for smartcard PIN -> insert correct smartcard PIN
        6. User is successfully logged in
        7. Try to switch to root (su -)

    Expected result
        - User is asked to insert root password
        - User inserts root password
        - User is switched to the root user
    """
    with Authselect(required=True):
        with VirtCard(ipa_user.USERNAME, insert=True):
            cmd = f"su {ipa_user.USERNAME} -c 'su {ipa_user.USERNAME}'"
            shell = run_cmd(cmd, return_val="shell")
            shell.expect(f"PIN for {ipa_user.USERNAME}", timeout=10)
            shell.sendline(ipa_user.PIN)
            shell.sendline("su - -c 'whoami'")
            shell.expect("Password")
            shell.sendline(ipa_user.ROOT_PASSWD)
            shell.expect("root")


def test_krb_user_su_to_root_wrong_passwd_sc_required_no_sc(ipa_user, user_shell):
    """Kerberos user tries to switch to the root user with root password after
       kerberos user is logged in with smart card. Smart card is required.

       Setup
           1. General setup
           2. Setup authselect: authselect select sssd with-smartcard with-smartcard-required
           3. Insert the card
           4. Switch to kerberos user (su kerberos_username)
           5. System asks for smartcard PIN -> insert correct smartcard PIN
           6. User is successfully logged in
           7. Try to switch to root (su -)

       Expected result
           1. User is asked to insert root password
           2. User inserts wrong root password
           3. User is not switched to the root user, corresponding message is
              written to the output
       """
    with Authselect(required=True):
        with VirtCard(username=ipa_user.USERNAME, insert=True) as sc:
            cmd = f"su {ipa_user.USERNAME}"
            user_shell.sendline(cmd)
            user_shell.expect_exact(f"PIN for {ipa_user.USERNAME}:")
            user_shell.sendline(ipa_user.PIN)
            cmd = "whoami"
            user_shell.sendline(cmd)
            user_shell.expect_exact(ipa_user.USERNAME)
            sc.remove()

            cmd = "su -"
            user_shell.sendline(cmd)
            user_shell.expect_exact("Password:")
            user_shell.sendline("wrong_password")
            user_shell.expect_exact("su: Authentication failure")


def test_kerberos_user_sudo_wrong_password(ipa_user, user_shell):
    """Kerberos user tries to use sudo to access some application and mistype
    the password. Smartcard is required and used for user login and removed
    after login.

    Setup
        1. General setup
        2. Setup authselect: authselect select sssd with-smartcard with-smartcard-required
        3. Insert the card
        4. Switch to kerberos user (su kerberos_username)
        5. System asks for smartcard PIN -> insert correct smartcard PIN
        6. User is successfully logged in
        7. Try to run sudo command 'sudo ls /'

    Expected result
        - User is asked to insert the password
        - User inserts wrong password
        - Password is not accepted and user is asked to insert the password again
    """

    with Authselect(required=True):
        with VirtCard(username=ipa_user.USERNAME, insert=True) as sc:
            cmd = f"su - {ipa_user.USERNAME} -c 'sudo -S ls /'"
            user_shell.sendline(cmd)
            user_shell.expect_exact(f"PIN for {ipa_user.USERNAME}:")
            user_shell.sendline(ipa_user.PIN)

            cmd = "whoami"
            user_shell.sendline(cmd)
            user_shell.expect_exact(ipa_user.USERNAME)

            sc.remove()

            cmd = "sudo -S ls /"
            user_shell.sendline(cmd)
            user_shell.expect_exact(f"[sudo] password for {ipa_user.USERNAME}:")
            user_shell.sendline("098765432")
            user_shell.expect("Sorry, try again.")


def test_krb_user_sudo_correct_password_sc_required_no_sc(ipa_user, user_shell):
    with Authselect(required=True):
        with VirtCard(username=ipa_user.USERNAME, insert=True) as sc:
            output = pexpect.run("ls /", encoding="utf-8")
            cmd = f"su - {ipa_user.USERNAME}"
            user_shell.sendline(cmd)
            user_shell.expect_exact(f"PIN for {ipa_user.USERNAME}:")
            user_shell.sendline(ipa_user.PIN)

            cmd = "whoami"
            user_shell.sendline(cmd)
            user_shell.expect_exact(ipa_user.USERNAME)

            sc.remove()

            cmd = "sudo -S ls /"
            user_shell.sendline(cmd)
            user_shell.expect(rf"\[sudo\] password for {ipa_user.USERNAME}:")
            user_shell.sendline(ipa_user.PASSWD)
            user_shell.expect(output)
