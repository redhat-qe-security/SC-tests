"""
This module contains tests for logging into GUI using GDM.
Most of the tests are parametrized to test both
optional and required smart card in authselect.
Lock-on-removal option is not set as it is irelevent for present tests.
The tests within the module try logging in both using password and
smart card with PIN. Both wrong password and wrong PIN are tested too.
All tests depend on SCAutolib GUI module.

If not stated otherwise tests in this module use virtual cards
and share the following setup steps:
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
"""

from SCAutolib.models.authselect import Authselect
from SCAutolib.models.gui import GUI
from SCAutolib.models.log import assert_log
import pytest
from time import sleep

SECURE_LOG = '/var/log/secure'


@pytest.mark.parametrize("required", [(True), (False)])
def test_login_with_sc(local_user, required):
    """Local user logs in with GDM, using smart card with correct PIN.

    Test steps
        A. Configure SSSD:
            authselect select sssd with-smartcard
            OR
            authselect select sssd with-smartcard with-smartcard-required
        B. Start GDM
        C. Insert the card and type the correct PIN

    Expected result
        A. Configuration is updated
        B. GDM starts successfully
        C. User is asked for smartcard PIN and
            logged into GNOME desktop environment successfully
    """
    expected_log = (
        r'.* gdm-smartcard\]\[[0-9]+\]: '
        r'pam_sss\(gdm-smartcard:auth\): authentication success;'
        r'.*user=' + local_user.username + r'@shadowutils.*'
    )

    with Authselect(required=required), local_user.card(insert=True), GUI() as gui:
        gui.assert_text('PIN')
        gui.kb_write(local_user.pin)

        with assert_log(SECURE_LOG, expected_log):
            gui.kb_send('enter', wait_time=20)
        # Mandatory wait to switch display from GDM to GNOME
        # Not waiting can actually mess up the output
        gui.assert_text('Activities')


@pytest.mark.parametrize("required", [(True), (False)])
def test_login_with_sc_wrong(local_user, required):
    """Local user tries to log in with GDM, using smart card with wrong PIN.

    Test steps
        A. Configure SSSD:
            authselect select sssd with-smartcard
            OR
            authselect select sssd with-smartcard with-smartcard-required
        B. Start GDM
        C. Insert the card and type an incorrect PIN

    Expected result
        A. Configuration is updated
        B. GDM starts successfully
        C. A message about incorrect PIN is displayed and user is not logged in.
    """
    expected_log = (
        r'.* gdm-smartcard\]\[[0-9]+\]: '
        r'pam_sss\(gdm-smartcard:auth\): authentication failure;'
        r'.*user=' + local_user.username + r'@shadowutils.*'
    )

    with Authselect(required=required), local_user.card(insert=True), GUI() as gui:
        gui.assert_text('PIN')
        gui.kb_write(local_user.pin[:-1])

        with assert_log(SECURE_LOG, expected_log):
            gui.kb_send('enter', wait_time=20)
        # Mandatory wait to switch display from GDM to GNOME
        # Not waiting can actually mess up the output
        gui.assert_no_text('Activities')
        gui.assert_text('PIN')


def test_login_password(local_user):
    """Local user logs in with GDM using his password.

    Test steps
        A. Configure SSSD:
            authselect select sssd with-smartcard
        B. Start GDM
        C. Login as the user in GDM using password

    Expected result
        A. Configuration is updated
        B. GDM starts successfully
        C. User is successfully logged into GNOME desktop environment
    """
    expected_log = (
        r'.* pam_unix\(gdm-password:session\): session opened for user .*'
        )

    with Authselect(required=False), GUI() as gui:
        gui.click_on(local_user.username)
        gui.kb_write(local_user.password)
        with assert_log(SECURE_LOG, expected_log):
            gui.kb_send('enter', wait_time=20)
        gui.assert_text('Activities')


def test_login_password_wrong(local_user):
    """Local user tries to log in with GDM using incorrect password.

    Test steps
        A. Configure SSSD:
            authselect select sssd with-smartcard
        B. Start GDM
        C. Try to log in using wrong password

    Expected result
        A. Configuration is updated
        B. GDM starts successfully
        C. A message about incorrect password is displayed
            and login is unsuccessful.
    """
    expected_log = (
        r'.* gdm-password\]\[[0-9]+\]: '
        r'pam_unix\(gdm-password:auth\): authentication failure;'
        r'.*user=' + local_user.username + r'.*'
    )

    with Authselect(required=False), GUI() as gui:
        gui.click_on(local_user.username)
        gui.kb_write(local_user.password[:-1])
        with assert_log(SECURE_LOG, expected_log):
            gui.kb_send('enter', wait_time=20)

        gui.assert_no_text('Activities')
        gui.assert_text('Password')


def test_insert_card_prompt(local_user):
    """Local user tries to log in with GDM before inserting card,
        with sc required.

        Test steps
        A. Configure SSSD:
            authselect select sssd with-smartcard
        B. Start GDM
        C. Insert the smart card
        D. Type the card's PIN

    Expected result
        A. Configuration is updated
        B. GDM starts successfully and "insert card" message is displayed
        C. GDM shows "insert PIN" prompt
        D. User is logged in successfully.
    """
    with (Authselect(required=True),
          local_user.card(insert=False) as card,
          GUI() as gui):
        gui.assert_text('insert')
        card.insert()
        sleep(10)
        gui.assert_text('PIN')
        gui.kb_write(local_user.pin)

        expected_log = (
            r'.* gdm-smartcard\]\[[0-9]+\]: '
            r'pam_sss\(gdm-smartcard:auth\): authentication success;'
            r'.*user=' + local_user.username + r'@shadowutils.*'
        )

        with assert_log(SECURE_LOG, expected_log):
            gui.kb_send('enter', wait_time=20)
        # Mandatory wait to switch display from GDM to GNOME
        # Not waiting can actually mess up the output
        gui.assert_text('Activities')
