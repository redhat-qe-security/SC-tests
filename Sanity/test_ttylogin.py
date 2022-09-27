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
