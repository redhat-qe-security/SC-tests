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

@pytest.mark.parametrize("service,should_pass", [
    ("-su", False),
    ("+pam_cert_service", True)
])
def test_pam_services_config(
    local_user, root_shell, sssd, service, should_pass
):
    """Test verifies that sssd configuration option pam_p11_allowed_services
    works as expected for smart card authentication.
    GitHub issue: https://github.com/SSSD/sssd/issues/3967"""
    with open("/etc/pam.d/pam_cert_service", "w") as f:
        f.write("auth\trequired\tpam_sss.so require_cert_auth\n")
    with sssd(section="pam", key="pam_p11_allowed_services", value=service) as sssd_conf:
        with local_user.card(insert=False) as sc:
            cmd = "sssctl user-checks -a auth -s pam_cert_service " \
                  f"{local_user.username}"
            root_shell.sendline(cmd)
            root_shell.expect_exact("Please insert smart card")
            sc.insert()
            if should_pass:
                root_shell.expect_exact(f"PIN for {local_user.username}:")
                root_shell.sendline(local_user.pin)
                root_shell.expect_exact(f"pam_authenticate for user "
                                        f"[{local_user.username}]: Success")
            else:
                fail = f"pam_authenticate for user [{local_user.username}]: " \
                   "Authentication service cannot retrieve authentication info"
                root_shell.expect_exact("Please (re)insert (different) Smartcard")
                root_shell.sendline()
                root_shell.expect_exact(fail)


def test_physical_card_detection(local_user, root_shell):
    for i in range(local_user.total_cards):
        with getattr(local_user, f"card_{i}") as sc:
            cmd = "pkcs11-tool -L"
            root_shell.sendline(cmd)
            root_shell.expect_exact("(empty)")
            sc.insert()
            root_shell.sendline(cmd)
            root_shell.expect_exact(sc.label)
