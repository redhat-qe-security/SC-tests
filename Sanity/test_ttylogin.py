"""
This module contains tests that approximates testing of SC login in virtual
console. They are implemented as execution of login command in pexpect.

Login prompt in virtual console appears as a result of systemd running agetty
service that executes getty command to get TTY and executes login command in
that TTY. Therefore, execution of login command in nearly the same way agetty
does it is good approximation to manual testing in virtual console.
"""
import sys
from time import sleep

import pexpect
import pytest

from SCAutolib.models.authselect import Authselect


def login_shell_factory(username):
    """Returns login shell for username."""
    shell = pexpect.spawn(f"login {username}",
                          ignore_sighup=True, encoding="utf-8")
    shell.logfile = sys.stdout
    sleep(3)
    return shell


def test_login_with_sc(user):
    """Console-like login to the user with a smart card.
    Setup
        1. Create local CA
        2. Create virtual smart card with certs signed by created CA
        3. Update /etc/sssd/sssd.conf so it contains following fields
            [sssd]
            debug_level = 9
            services = nss, pam,
            domains = shadowutils
            certificate_verification = no_ocsp
            [pam]
            debug_level = 9
            pam_cert_auth = True
            [domain/shadowutils]
            debug_level = 9
            id_provider = files
            [certmap/shadowutils/username]
            matchrule = <SUBJECT>.*CN=username.*
        4. Setup authselect: authselect select sssd with-smartcard
        5. Insert the card
        6. Login as smartcard user (`exec login $USERNAME` from root shell)
    Expected result
        - Users is asked for smartcard PIN
        - User insert correct PIN
        - User is successfully logged in
    """
    with Authselect():
        with user.card(insert=True):
            login_shell = login_shell_factory(user.username)
            login_shell.expect([f"PIN for {user.username}:"])
            login_shell.sendline(user.pin)
            login_shell.expect([user.username])
            login_shell.sendline("exit")
            login_shell.close()


def test_login_without_sc(user):
    """Console-like login to the user without a smart card.
    Setup
        1. Create local CA
        2. Create virtual smart card with certs signed by created CA
        3. Update /etc/sssd/sssd.conf so it contains following fields
            [sssd]
            debug_level = 9
            services = nss, pam,
            domains = shadowutils
            certificate_verification = no_ocsp
            [pam]
            debug_level = 9
            pam_cert_auth = True
            [domain/shadowutils]
            debug_level = 9
            id_provider = files
            [certmap/shadowutils/username]
            matchrule = <SUBJECT>.*CN=username.*
        4. Setup authselect: authselect select sssd with-smartcard
        5. Login as smartcard user (`exec login $USERNAME` from root shell)
    Expected result
        - Users is asked for password
        - User insert correct password
        - User is successfully logged in
    """
    with Authselect():
        login_shell = login_shell_factory(user.username)
        login_shell.expect(f"Password:")
        login_shell.sendline(user.password)
        login_shell.expect(user.username)
        login_shell.sendline("exit")
        login_shell.close()


def test_login_without_sc_wrong(user):
    """Basic login to the user without a smartcard when user enters wrong password.

    Setup
    1. Create local CA
    2. Create virtual smart card with certs signed by created CA
    3. Update /etc/sssd/sssd.conf so it contains following fields
        [sssd]
        debug_level = 9
        services = nss, pam,
        domains = shadowutils
        certificate_verification = no_ocsp

        [pam]
        debug_level = 9
        pam_cert_auth = True

        [domain/shadowutils]
        debug_level = 9
        id_provider = files

        [certmap/shadowutils/username]
        matchrule = <SUBJECT>.*CN=username.*
    4. Setup authselect: authselect select sssd with-smartcard
    5. Insert the card
    6. Try to switch user (su login) to the smartcard user


    Expected result
        - Users is asked for smartcard PIN
        - User inserts wrong PIN
        - User is not logged in and error message is written to the console
    """
    with Authselect():
        login_shell = login_shell_factory(user.username)
        login_shell.expect(f"Password:")
        login_shell.sendline("wrong")
        login_shell.expect("Login incorrect")
        login_shell.sendline("exit")
        login_shell.close()


def test_login_with_sc_required(user):
    """Console-like login to the user with a smart card; smartcard required.
    Setup
        1. Create local CA
        2. Create virtual smart card with certs signed by created CA
        3. Update /etc/sssd/sssd.conf so it contains following fields
            [sssd]
            debug_level = 9
            services = nss, pam,
            domains = shadowutils
            certificate_verification = no_ocsp
            [pam]
            debug_level = 9
            pam_cert_auth = True
            [domain/shadowutils]
            debug_level = 9
            id_provider = files
            [certmap/shadowutils/username]
            matchrule = <SUBJECT>.*CN=username.*
        4. Setup authselect: authselect select sssd with-smartcard
           with-smartcard-required
        5. Insert the card
        6. Login as smartcard user (`exec login $USERNAME` from root shell)
    Expected result
        - Users is asked for smartcard PIN
        - User insert correct PIN
        - User is successfully logged in
    """
    with Authselect(required=True):
        with user.card(insert=True):
            login_shell = login_shell_factory(user.username)
            login_shell.expect([f"PIN for {user.username}:", pexpect.EOF])
            login_shell.sendline(user.pin)
            login_shell.expect([user.username, pexpect.EOF])
            login_shell.sendline("exit")
            login_shell.close()


@pytest.mark.parametrize("required", [True, False])
def test_login_with_sc_wrong(user, required):
    """Console-like login to the user with a smart card.

    Setup
        1. Create local CA
        2. Create virtual smart card with certs signed by created CA
        3. Update /etc/sssd/sssd.conf so it contains following fields
            [sssd]
            debug_level = 9
            services = nss, pam,
            domains = shadowutils
            certificate_verification = no_ocsp
            [pam]
            debug_level = 9
            pam_cert_auth = True
            [domain/shadowutils]
            debug_level = 9
            id_provider = files
            [certmap/shadowutils/username]
            matchrule = <SUBJECT>.*CN=username.*
        4. Setup authselect: authselect select sssd with-smartcard
        5. Insert the card
        6. Login as smartcard user (`exec login $USERNAME` from root shell)

    Expected result
        - User is asked for smartcard PIN
        - User inserts wrong PIN
        - User is told that the PIN is incorrect
    """
    with Authselect(required=required):
        with user.card(insert=True):
            login_shell = login_shell_factory(user.username)
            login_shell.expect(f"PIN for {user.username}:")
            # Omit the last digit of the PIN
            login_shell.sendline(user.pin[:-1])
            login_shell.expect("Login incorrect")
            login_shell.close()


@pytest.mark.parametrize("lock_on_removal", [True, False])
def test_login_sc_required(user, lock_on_removal):
    """Console-like login to the user with a smart card.

    Setup
        1. Create local CA
        2. Create virtual smart card with certs signed by created CA
        3. Update /etc/sssd/sssd.conf so it contains following fields
            [sssd]
            debug_level = 9
            services = nss, pam,
            domains = shadowutils
            certificate_verification = no_ocsp
            [pam]
            debug_level = 9
            pam_cert_auth = True
            [domain/shadowutils]
            debug_level = 9
            id_provider = files
            [certmap/shadowutils/username]
            matchrule = <SUBJECT>.*CN=username.*
        4. Setup authselect: authselect select sssd with-smartcard with-smartcard-required
        5. Try to login without smart-card unsuccessfully
        6. Insert the card
        7. Log in

    Expected result
        - User is prompted to insert the card
        - User inserts the card
        - User types PIN the PIN
        - User is successfully logged in
    """
    with Authselect(required=True, lock_on_removal=lock_on_removal):
        login_shell = login_shell_factory(user.username)
        login_shell.expect("Please insert smart card")

        with user.card(insert=True):
            login_shell.expect(f"PIN for {user.username}:")
            login_shell.sendline(user.pin)
            login_shell.expect(user.username)
            login_shell.sendline("exit")
            login_shell.close()

@pytest.mark.parametrize(
        "required,lock_on_removal", [(True, True), (True, False), (False, True), (False, False),]
    )
def test_login_local_user_passwd(user, required, lock_on_removal):
    """Run 'passwd' command when smartcard login is enforced and after user is
    authenticated in with a smartcard.

    Setup
        1. Create local CA
        2. Create virtual smart card with certs signed by created CA
        3. Update /etc/sssd/sssd.conf so it contains following fields
            [sssd]
            debug_level = 9
            services = nss, pam,
            domains = shadowutils
            certificate_verification = no_ocsp

            [pam]
            debug_level = 9
            pam_cert_auth = True

            [domain/shadowutils]
            debug_level = 9
            id_provider = files

            [certmap/shadowutils/username]
            matchrule = <SUBJECT>.*CN=username.*
        4. Setup authselect: authselect select sssd with-smartcard (with-smartcard-required)
        5. Login to the smart card user
        6. Run 'passwd'


    Expected result
        - Users is asked to change it local password
        - No mentioning of the smart card
    """

    with Authselect(required=required, lock_on_removal=lock_on_removal):
        with user.card(insert=True):
            login_shell = login_shell_factory(user.username)
            login_shell.expect([f"PIN for {user.username}:"])
            login_shell.sendline(user.pin)
            login_shell.expect([user.username])
            login_shell.sendline("passwd")
            login_shell.expect_exact(f"Changing password for user {user.username}.")

@pytest.mark.parametrize(
    "required,lock_on_removal", [(True, True), (True, False), (False, True), (False, False),]
)
def test_login_local_su_to_root(user, root_user, required, lock_on_removal):
    """Test for smartcard login to the local user and then switching to root (su -).

    Setup
        1. Create local CA
        2. Create virtual smart card with certs signed by created CA
        3. Update /etc/sssd/sssd.conf so it contains following fields
            [sssd]
            debug_level = 9
            services = nss, pam,
            domains = shadowutils
            certificate_verification = no_ocsp

            [pam]
            debug_level = 9
            pam_cert_auth = True

            [domain/shadowutils]
            debug_level = 9
            id_provider = files

            [certmap/shadowutils/username]
            matchrule = <SUBJECT>.*CN=username.*
        4. Setup authselect: authselect select sssd with-smartcard
        5. Insert the card
        6. Switch user with 'su' command to the smartcard user
        7. User is asked for smartcard PIN -> insert correct PIN
        8. After successful login, try to switch to root user with 'su -'

    Expected result
        - Users is asked for root password
        - User insert correct root password
        - User is switched to the root user
    """
    with Authselect(required=required, lock_on_removal=lock_on_removal):
        with user.card(insert=True):
            login_shell = login_shell_factory(user.username)
            login_shell.expect([f"PIN for {user.username}:"])
            login_shell.sendline(user.pin)
            login_shell.expect([user.username])
            login_shell.sendline("whoami")
            login_shell.expect_exact(user.username)
            login_shell.sendline('su - root -c "whoami"')
            login_shell.expect_exact("Password:")
            login_shell.sendline(root_user.password)
            login_shell.expect_exact("root")

@pytest.mark.parametrize("required", [True, False])
def test_login_kerberos_su_to_root(ipa_user, root_user, required):
    """Kerberos user tries to switch to the root user with root password after
    kerberos user is logged in with smart card.

    Setup
        1. General setup
        2. Setup authselect: authselect select sssd with-smartcard with-smartcard-required
        3. Insert the card
        4. Login to kerberos user
        5. System asks for smartcard PIN -> insert correct smartcard PIN
        6. User is successfully logged in
        7. Try to switch to root (su -)

    Expected result
        - User is asked to insert root password
        - User inserts root password
        - User is switched to the root user
    """
    with Authselect(required=required):
        with ipa_user.card(insert=True):
            login_shell = login_shell_factory(ipa_user.username)
            login_shell.expect([f"PIN for {ipa_user.username}:"])
            login_shell.sendline(ipa_user.pin)
            login_shell.expect([ipa_user.username])
            login_shell.sendline("whoami")
            login_shell.expect_exact(ipa_user.username)
            login_shell.sendline('su - root -c "whoami"')
            login_shell.expect_exact("Password:")
            login_shell.sendline(root_user.password)
            login_shell.expect_exact("root")