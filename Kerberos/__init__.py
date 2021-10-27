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
