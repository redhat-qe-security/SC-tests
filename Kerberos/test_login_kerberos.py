import pexpect
import pytest

from SCAutolib import run
from SCAutolib.models.authselect import Authselect


def test_smart_card_gdm_login_enforcing(ipa_user, root_shell):
    """Test kerberos user tries to login to the GDM with smart card. Smart
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
        with ipa_user.card(insert=False) as sc:
            cmd = f"sssctl user-checks -s gdm-smartcard {ipa_user.username} -a auth"
            root_shell.sendline(cmd)
            root_shell.expect(r"Please (insert|enter) smart card", timeout=10)
            sc.insert()
            root_shell.expect(f"PIN for {ipa_user.username}:")
            root_shell.sendline(ipa_user.pin)
            root_shell.expect(rf"pam_authenticate for user \[{ipa_user.username}\]: Success")


def test_kerberos_login_to_root(ipa_user, user_shell, root_user):
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
        with ipa_user.card(insert=True):
            user_shell.sendline(f"su - {ipa_user.username}")
            user_shell.expect(f"PIN for {ipa_user.username}", timeout=10)
            user_shell.sendline(ipa_user.pin)
            user_shell.expect(ipa_user.username)
            user_shell.sendline("su - -c 'whoami'")
            user_shell.expect("Password")
            user_shell.sendline(root_user.password)
            user_shell.expect("root")


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
        with ipa_user.card(insert=True) as sc:
            cmd = f"su - {ipa_user.username}"
            user_shell.sendline(cmd)
            user_shell.expect_exact(f"PIN for {ipa_user.username}:")
            user_shell.sendline(ipa_user.pin)
            cmd = "whoami"
            user_shell.sendline(cmd)
            user_shell.expect_exact(ipa_user.username)
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
        with ipa_user.card(insert=True) as sc:
            cmd = f"su - {ipa_user.username} -c 'sudo -S ls /'"
            user_shell.sendline(cmd)
            user_shell.expect_exact(f"PIN for {ipa_user.username}:")
            user_shell.sendline(ipa_user.pin)

            cmd = "whoami"
            user_shell.sendline(cmd)
            user_shell.expect_exact(ipa_user.username)

            sc.remove()

            cmd = "sudo -S ls /"
            user_shell.sendline(cmd)
            user_shell.expect_exact(f"[sudo] password for {ipa_user.username}:")
            user_shell.sendline("098765432")
            user_shell.expect("Sorry, try again.")


def test_krb_user_sudo_correct_password_sc_required_no_sc(ipa_user, user_shell, allow_sudo_commands):
    with Authselect(required=True, sudo=True):
        with ipa_user.card(insert=True) as sc:
            output = pexpect.run("ls /", encoding="utf-8")
            cmd = f"su - {ipa_user.username}"
            user_shell.sendline(cmd)
            user_shell.expect_exact(f"PIN for {ipa_user.username}:")
            user_shell.sendline(ipa_user.pin)

            cmd = "whoami"
            user_shell.sendline(cmd)
            user_shell.expect_exact(ipa_user.username)

            sc.remove()

            cmd = "sudo -S ls /"
            user_shell.sendline(cmd)
            user_shell.expect(rf"\[sudo\] password for {ipa_user.username}:")
            user_shell.sendline(ipa_user.password)
            user_shell.expect(output)


def test_krb_user_su_correct_password(ipa_user, user_shell):
    """Kerberos' user login with command su using correct password.

    Setup:
        1. General setup
        2. Smart card is NOT required for login
        3. Smart card is NOT inserted
        4. Run su ipa-user

    Expected result:
        - user is prompted to insert kerberos password
        - after inserting the password, user is successfully authenticated
    """
    with Authselect():
        cmd = f"su {ipa_user.username}"
        user_shell.sendline(cmd)
        user_shell.expect_exact("Password:")
        user_shell.sendline(ipa_user.password)
        user_shell.sendline("whoami")
        user_shell.expect_exact(ipa_user.username)
        user_shell.close()
