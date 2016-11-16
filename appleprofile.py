import os
import biplist
import uuid
import subprocess
import tempfile

# Generate a Apple Device Profile for configuring the Wi-Fi and VPN networks
# with EAP-TLS.
#
# p12cert must point to a valid on-desk .p12 (BER) key+certificate that is
# valid for EAP-TLS authentication.
#
# userid can be specified as ASCII identifier for the generated profile; this is used
# by Apple OS to differentiate between a new profile and a new version of an existing
# profile. A good example is to put the username here. If not specified, it defaults
# to the p12cert filename (without extensions)
#
# password is the optional certificate password to embed in the configuration profile.
# If the p12cert is encrypted and the password is not given here, the resulting profile
# will ask for the password during installation; if the password is specified, it will
# be embedded in the profile and thus nothing will be requested at installation time.
# NOTE: consider the security implications of putting the password witin the profile;
# the profile file will be self-contained and anybody getting it would be able to
# authenticate successfully.
#
# servcert is a BER server certificate to be trusted while connecting to the Wi-Fi
# network. WPA-Enterprise doesn't provide a system for server certificates to be
# automatically trusted (like the CA system in TLS), so if a certificate is not
# specified here, users will be shown a warning screen on the first connection, asking
# them to trust the server certificate.
# NOTE: you can either put the server certificate or self-signed CA (that signs the
# server certificate). Putting a CA will result in a warning screen at installation
# time, and the CA will be installed in the device and trusted for all connections
# including MIMT-like TLS (not only for this Wi-Fi connection).
#
def GenerateProfile(outfn, p12cert, userid=None, password=None, servercert=None):
    profile_uuid = str(uuid.uuid1())
    cert_uuid = str(uuid.uuid1())
    wifi_uuid = str(uuid.uuid1())
    vpn_uuid = str(uuid.uuid1())

    if userid is None:
        userid = os.path.splitext(os.path.basename(p12cert))[0]

    data = {
        "PayloadDisplayName": "Develer Staff Wi-Fi/VPN",
        "PayloadDescription": "This profile configures both a Wi-Fi and VPN connection to Develer",
        "PayloadIdentifier": "com.develer.staffconfig." + userid,
        "PayloadOrganization": "Develer S.r.l.",
        "PayloadRemovalDisallowed": False,
        "PayloadType": "Configuration",
        "PayloadUUID": profile_uuid,
        "PayloadVersion": 1,
        "PayloadContent": [
            {
                "PayloadDescription": "New PKCS#12 certificate",
                "PayloadDisplayName": "Develer LAN certificate for \"%s\"" % userid,
                "PayloadIdentifier": "com.apple.security.pkcs12." + cert_uuid,
                "PayloadType": "com.apple.security.pkcs12",
                "PayloadUUID": cert_uuid,
                "PayloadVersion": 1,

                "PayloadCertificateFileName": p12cert,
                "PayloadContent": biplist.Data(open(p12cert).read()),
                #"Password" here to embed the password (see below)
            },
            {
                "PayloadDescription": "Configure Wi-Fi settings",
                "PayloadDisplayName": "Wi-Fi",
                "PayloadIdentifier": "com.apple.wifi.managed." + wifi_uuid,
                "PayloadType": "com.apple.wifi.managed",
                "PayloadUUID": wifi_uuid,
                "PayloadVersion": 1,

                "AutoJoin": True,
                "CaptiveBypass": True,
                "EAPClientConfiguration": {
                    "AcceptEAPTypes": [13],
                    #"PayloadCertificateAnchorUUID": [cert_server_uuid],  # trusted server certs
                },
                "EncryptionType": "WPA2",
                "HIDDEN_NETWORK": True,
                "IsHotspot": False,
                "PayloadCertificateUUID": cert_uuid,
                "ProxyType": "None",
                "SSID_STR": "develer-staff",
            },
            {
                "PayloadDescription": "Configures VPN settings",
                "PayloadDisplayName": "VPN",
                "PayloadIdentifier": "com.apple.vpn.managed." + vpn_uuid,
                "PayloadType": "com.apple.vpn.managed",
                "PayloadUUID": vpn_uuid,
                "PayloadVersion": 1,

                "UserDefinedName": "Develer Staff VPN",
                "VPNType": "IKEv2",
                "IKEv2": {
                    "AuthenticationMethod": "Certificate",
                    "ChildSecurityAssociationParameters": {
                        "DiffieHellmanGroup": 14,
                        "EncryptionAlgorithm": "AES-256",
                        "IntegrityAlgorithm": "SHA2-256",
                        "LifeTimeInMinutes": 1440,
                    },
                    "DeadPeerDetectionRate": "Medium",
                    "DisableMOBIKE": 0,
                    "DisableRedirect": 0,
                    "EnableCertificateRevocationCheck": 0,
                    "EnablePFS": False,
                    "ExtendedAuthEnabled": False,
                    "IKESecurityAssociationParameters": {
                        "DiffieHellmanGroup": 14,
                        "EncryptionAlgorithm": "AES-256",
                        "IntegrityAlgorithm": "SHA2-256",
                        "LifeTimeInMinutes": 1440,
                    },
                    "LocalIdentifier": userid + "@develer.com",
                    "PayloadCertificateUUID": cert_uuid,
                    "RemoteAddress": "lan.vpn.develer.net",
                    "RemoteIdentifier": "lan.vpn.develer.net",
                    "ServerCertificateIssuerCommonName": "Develer LAN Certificate Authority",
                    "UseConfigurationAttributeInternalIPSubnet": 0,
                },
                "IPv4": {
                    "OverridePrimary": 0,
                },
                "Proxies": {
                    "HTTPEnable": 0,
                    "HTTPSEnable": 0,
                },
            },
        ],
    }

    if servercert:
        cert_server_uuid = str(uuid.uuid1())
        data["PayloadContent"].append({
            "PayloadDescription": "New PKCS#1 certificate",
            "PayloadDisplayName": "Develer LAN Server Certificate",
            "PayloadIdentifier": "com.apple.security.pkcs1." + cert_server_uuid,
            "PayloadType": "com.apple.security.pkcs1",
            "PayloadUUID": cert_server_uuid,
            "PayloadVersion": 1,
            "PayloadCertificateFileName": servercert,
            "PayloadContent": biplist.Data(open(servercert).read()),
        })

        # Change the wifi configuration to trust this server certificate
        data["PayloadContent"][1]["EAPClientConfiguration"]["PayloadCertificateAnchorUUID"] = [cert_server_uuid]

    if password:
        # Embed the certificate password within the device file.
        data["PayloadContent"][0]["Password"] = password

    biplist.writePlist(data, outfn)


# Generates a Apple device profile, with an embedded signature. Using a certificate
# that is trusted by the device will result in the profile be marked as "Verified"
# with a green check mark at installation time.
#
# Possible choices for valid certificates:
#  * A valid TLS certificate, like those used on webservers. The dialog will show
#    the server name to the user. So for instance if the certificate for "www.example.org"
#    is used to sign the profile, the user will see "Signed by: www.example.org".
#
#  * A valid code-signing certificate, obtained by a CA. In this case, the dialog
#    will show the name of company that owns the certificate (as it is usually
#    put in the certificate Common Name field). The user will see: "Signed by: Develer S.r.l.".
#
#  * A Apple-created macOS code-signing certificate (obtain through the Apple Developer Panel
#    for registered developers). This can be created for free. It is trusted on
#    macOS, but will appear as "Not verified" on iOS.
#
def GenerateSignedProfile(outfn, signkey, signcert, **kwargs):
    fd, tmpfn = tempfile.mkstemp()
    os.close(fd)
    try:
        GenerateProfile(tmpfn, **kwargs)
        subprocess.check_call([
            "openssl", "smime", "-sign", "-nodetach", "-binary",
            "-inkey", signkey,
            "-signer", signcert,
            "-certfile", signcert,
            "-in", tmpfn,
            "-outform", "der",
            "-out", outfn,
        ])
    finally:
        os.remove(tmpfn)
