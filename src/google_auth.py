import os
import requests
import json
from oauthlib.oauth2 import WebApplicationClient


# This article was very helpful in making this file
# https://realpython.com/flask-google-login/

GOOGLE_CLIENT_ID = os.getenv("CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("CLIENT_SECRET")
# Provides information on various endpoints
GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"

#OAuth 2 client setup
client = WebApplicationClient(GOOGLE_CLIENT_ID)

#The provider configuration
google_provider_config: dict = requests.get(GOOGLE_DISCOVERY_URL).json()

def login_redirect_uri(redirect_uri: str):
    """
        Returns the uri to redirect to when the login endpoint is reached.

        A redirect is made to `redirect_uri` once authorization is complete
    """

    # Get the url from the provider config
    authorization_endpoint: str = google_provider_config.get("authorization_endpoint")

    # Build the uri 
    uri = client.prepare_request_uri(
        uri=authorization_endpoint,
        redirect_uri=redirect_uri,
        scope=["openid", "email", "profile"], # The information access needed
    )

    return uri

def send_tokens(code, request_url, redirect_url):
    """
        Sends the tokens back to a google endpoint to get access to 
        user data. The client token is updated as a result.

        `code` is the access code provided after authorizaiton
    """

    # Get token endpoint
    token_endpoint = google_provider_config.get("token_endpoint")

    # prepare token request
    token_url, header, body = client.prepare_token_request(
        token_endpoint,
        authorization_response=request_url,
        redirect_url=redirect_url,
        code=code
    )

    # Send the post request
    token_response = requests.post(
        token_url,
        headers=header,
        data=body,
        auth=(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET)
    )

    client.parse_request_body_response(json.dumps(token_response.json()))

def get_user_data():
    """
        Send a request to Google for the profile information of a user
        
        Returns a dictionary with the fields, unique_id, email, name.
    """

    userinfo_endpoint = google_provider_config.get("userinfo_endpoint")

    uri, headers, body = client.add_token(userinfo_endpoint)
    # Send get request 
    userinfo_response = requests.get(uri, headers=headers, data=body)
    userinfo_response_json = userinfo_response.json()

    output = {
        "unique_id": userinfo_response_json.get("sub", ""),
        "email": userinfo_response_json.get("email", ""),
        "name" : userinfo_response_json.get("given_name", "")
    }

    return output
