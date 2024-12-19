import os
import configparser
from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
from saml2.client import Saml2Client
from saml2.config import Config as Saml2Config
from saml2.saml import NAMEID_FORMAT_TRANSIENT

# Read configuration from INI file
def load_config():
    config = configparser.ConfigParser()
    ini_path = os.path.join(os.path.dirname(__file__), 'config.ini')
    config.read(ini_path)
    return config

# Load configuration
config = load_config()

LOGIN_URL = config['DEFAULT']['LOGIN_URL']
LOGOUT_URL = config['DEFAULT']['LOGOUT_URL']
ASSERTION_CONSUMER_SERVICE = config['DEFAULT']['ASSERTION_CONSUMER_SERVICE']
THUMBPRINT = config['DEFAULT']['THUMBPRINT']
APPLICATION_ID = config['DEFAULT']['APPLICATION_ID']

# Dynamically construct ENTITY_ID from LOGIN_URL without altering its content
ENTITY_ID = f"{LOGIN_URL.replace("/saml2","").replace('login.microsoftonline.com', 'sts.windows.net')}/"

# SAML client setup
def create_saml_client():
    metadata_url = f"{LOGIN_URL.replace("/saml2", "")}/federationmetadata/2007-06/federationmetadata.xml"
    config = Saml2Config()
    config.load({
        "entityid": ENTITY_ID,
        "service": {
            "sp": {
                "endpoints": {
                    "assertion_consumer_service": [(ASSERTION_CONSUMER_SERVICE, BINDING_HTTP_POST)],
                },
                "allow_unsolicited": True,
            }
        },
        "metadata": {
            "remote": [
                {"url": metadata_url}
            ],
        },
        "xmlsec_binary": r".\xmlsec.exe",
    })
    return Saml2Client(config=config)

# Generate authentication request and print login URL
def authenticate(client: Saml2Client):
    authn_request = client.prepare_for_authenticate(
        entityid=ENTITY_ID,
        relay_state="",
        binding=BINDING_HTTP_REDIRECT,
        nameid_format=NAMEID_FORMAT_TRANSIENT
    )

    # Full redirect URL is returned as authn_request[0]
    redirect_url = authn_request[1].get("headers")[0][1]
    print("\nRedirect the user to the following URL to authenticate:")
    print(redirect_url)

# Main execution
def main():
    client = create_saml_client()
    authenticate(client)

if __name__ == "__main__":
    main()