"""
This module contains tests for logging into GUI using GDM.
Most of the tests are parametrized to test both
optional and required smart card in authselect.
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
from conftest import check_multicert

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
        rf'.*user=({local_user.username}@shadowutils)?.*'
    )

    with (GUI(wait_time=10) as gui, Authselect(required=required)):
        for i in range(local_user.total_cards):
            with getattr(local_user, f"card_{i}")(insert=True) as sc:
                check_multicert(gui=gui)
                gui.assert_text('PIN', timeout=60)

                with assert_log(SECURE_LOG, expected_log):
                    gui.kb_write(sc.pin)
                # Mandatory wait to switch display from GDM to GNOME
                # Not waiting can actually mess up the output
                gui.check_home_screen()


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
        rf'.*user=({local_user.username}@shadowutils)?.*'
    )

    with (GUI(wait_time=10) as gui, Authselect(required=required)):
        for i in range(local_user.total_cards):
            with getattr(local_user, f"card_{i}")(insert=True) as sc:
                multicert = check_multicert(gui=gui)
                gui.assert_text('PIN', timeout=20)

                with assert_log(SECURE_LOG, expected_log):
                    gui.kb_write(sc.pin[:-1])
                # Mandatory wait to switch display from GDM to GNOME
                # Not waiting can actually mess up the output
                gui.check_home_screen(False)
                if multicert:
                    gui.assert_text('certificate', timeout=20)
                else:
                    gui.assert_text('PIN', timeout=20)


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

    with GUI(wait_time=10) as gui, Authselect(required=False):
        gui.click_on(local_user.username)
        with assert_log(SECURE_LOG, expected_log):
            gui.kb_write(local_user.password)
        gui.check_home_screen()


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
        rf'.*user=({local_user.username}@shadowutils)?.*'
    )

    with GUI(wait_time=10) as gui, Authselect(required=False):
        gui.click_on(local_user.username)
        with assert_log(SECURE_LOG, expected_log):
            gui.kb_write(local_user.password[:-1])

        gui.check_home_screen(False)
        gui.assert_text('Password', timeout=20)


@pytest.mark.parametrize("lock_on_removal", [True, False])
def test_insert_card_prompt(local_user, lock_on_removal):
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
    with (GUI(wait_time=10) as gui,
          Authselect(required=True, lock_on_removal=lock_on_removal)):
        for i in range(local_user.total_cards):
            with getattr(local_user, f"card_{i}")(insert=True) as sc:
                try:
                    gui.assert_text('insert', timeout=20)
                except Exception:
                    gui.click_on(local_user.username)

                gui.assert_text('insert', timeout=20)
                sc.insert()
                sleep(10)
                check_multicert(gui=gui)
                gui.assert_text('PIN')

                expected_log = (
                    r'.* gdm-smartcard\]\[[0-9]+\]: '
                    r'pam_sss\(gdm-smartcard:auth\): authentication success;'
                    rf'.*user=({local_user.username}@shadowutils)?.*'
                )

                with assert_log(SECURE_LOG, expected_log):
                    gui.kb_write(sc.pin)
                # Mandatory wait to switch display from GDM to GNOME
                # Not waiting can actually mess up the output
                gui.check_home_screen()
