import pytest

from fixtures import user_indirect, root_shell, edit_config
from SCAutolib.src import virt_card, utils


def test_modutil_token_info(user, root_shell):
    """Check that p11-kit module shows smart card information with modutil
    command"""
    cmd = "modutil -list -dbdir /etc/pki/nssdb"
    uri = f"pkcs11:token={user.USERNAME_LOCAL};manufacturer=Common%20Access" \
          f"%20Card;serial=000058bd002c19b5;model=PKCS%2315%20emulated"
    with virt_card.VirtCard(user.USERNAME_LOCAL, insert=True):
        root_shell.sendline(cmd)
        root_shell.expect_exact(uri)


@pytest.mark.parametrize("file_path,section,key,value,restore,restart",
                         [("/etc/sssd/sssd.conf", "pam",
                           "pam_p11_allowed_services", "-su", True, ["sssd"])])
def test_pam_services_config(user, root_shell, edit_config):
    """Test for PAM configuration for smart card authentication.
    GitHub issue: https://github.com/SSSD/sssd/issues/3967"""
    with open("/etc/pam.d/pam_cert_service", "w") as f:
        f.write("auth\trequired\tpam_sss.so require_cert_auth")
    with virt_card.VirtCard(user.USERNAME_LOCAL, insert=True):
        cmd = "sssctl user-checks -a auth -s pam_cert_service " \
              f"{user.USERNAME_LOCAL}"
        root_shell.sendline(cmd)
        fail = f"pam_authenticate for user [{user.USERNAME_LOCAL}]: " \
               "Authentication service cannot retrieve authentication info"
        root_shell.expect_exact("Please insert smart card")
        root_shell.expect_exact("Password:")
        root_shell.sendline(user.PASSWD_LOCAL)
        root_shell.expect_exact(fail)

        utils.edit_config_("/etc/sssd/sssd.conf", "pam",
                           "pam_p11_allowed_services", "+pam_cert_service")
        utils.restart_service("sssd")

        root_shell.sendline(cmd)
        root_shell.expect_exact(f"PIN for {user.USERNAME_LOCAL}:")
        root_shell.sendline(user.PIN_LOCAL)
        root_shell.expect_exact(f"pam_authenticate for user [{user.USERNAME_LOCAL}]: Success")
