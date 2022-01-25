from fixtures import user_indirect, root_shell
from SCAutolib.src import virt_card


def test_modutil_token_info(user, root_shell):
    cmd = "modutil -list -dbdir /etc/pki/nssdb"
    uri = f"pkcs11:token={user.USERNAME_LOCAL};manufacturer=Common%20Access" \
          f"%20Card;serial=000058bd002c19b5;model=PKCS%2315%20emulated"
    with virt_card.VirtCard(user.USERNAME_LOCAL, insert=True):
        root_shell.sendline(cmd)
        root_shell.expect_exact(uri)
