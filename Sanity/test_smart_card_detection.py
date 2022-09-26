import pytest


def test_modutil_token_info(local_user, root_shell):
    """Check that p11-kit module shows smart card information with modutil
    command"""
    cmd = "modutil -list -dbdir /etc/pki/nssdb"
    uri = f"pkcs11:token={local_user.username};manufacturer=Common%20Access" \
          f"%20Card;serial=000058bd002c19b5;model=PKCS%2315%20emulated"
    with local_user.card(insert=True):
        root_shell.sendline(cmd)
        root_shell.expect_exact(uri)


def test_pam_services_config(local_user, root_shell, sssd):
    """Test for PAM configuration for smart card authentication.
    GitHub issue: https://github.com/SSSD/sssd/issues/3967"""
    with open("/etc/pam.d/pam_cert_service", "w") as f:
        f.write("auth\trequired\tpam_sss.so require_cert_auth")
    with sssd(section="pam", key="pam_p11_allowed_services", value="-su") as sssd_conf:
        with local_user.card(insert=False) as sc:
            cmd = "sssctl user-checks -a auth -s pam_cert_service " \
                  f"{local_user.username}"
            root_shell.sendline(cmd)
            fail = f"pam_authenticate for user [{local_user.username}]: " \
                   "Authentication service cannot retrieve authentication info"
            root_shell.expect_exact("Please insert smart card")
            sc.insert()
            root_shell.expect_exact("Password:")
            root_shell.sendline(local_user.password)
            root_shell.expect_exact(fail)
            sc.remove()

            sssd_conf(section="pam",
                      key="pam_p11_allowed_services",
                      value="+pam_cert_service")

            root_shell.sendline(cmd)
            root_shell.expect_exact("Please insert smart card")
            sc.insert()
            root_shell.expect_exact(f"PIN for {local_user.username}:")
            root_shell.sendline(local_user.pin)
            root_shell.expect_exact(f"pam_authenticate for user "
                                    f"[{local_user.username}]: Success")
