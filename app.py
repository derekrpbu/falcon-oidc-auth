import falcon, json, requests, os
from authlib.integrations.requests_client import OAuth2Session
from dotenv import load_dotenv

# take env variables from .env
load_dotenv()

# OIDC Provider Configuration
client_id = os.getenv('client_id')
client_secret = os.getenv('client_secret')

scope = ['openid', 'https://www.googleapis.com/auth/userinfo.email', 'https://www.googleapis.com/auth/userinfo.profile']
redirect_uri = 'http://localhost:8000/api/hello'
authorization_endpoint = "https://accounts.google.com/o/oauth2/auth"
token_endpoint = 'https://www.googleapis.com/oauth2/v3/token'
authorization_response = ''

# Create an OAuth2Session instance
oauth2_client = OAuth2Session(client_id, client_secret,redirect_uri=redirect_uri, scope=scope)      

class MyResource:
    def on_get(self, req, resp):
        content = {
            'name': 'Derek',
            'country': 'Costa Rica'
        }
        resp.body = json.dumps(content)
        resp.status = falcon.HTTP_200


class AuthMiddleware:
    def __init__(self, oauth2_client):
        self.oauth2_client = oauth2_client

    def process_request(self, req, resp):
        if req.path.startswith("/api"):
            try:
                authorization_response = req.url
                token = oauth2_client.fetch_token(token_endpoint, authorization_response=authorization_response)
                print("Token", token)   # Use the token for authenticated requests
                claims = oauth2_client.get("https://openidconnect.googleapis.com/v1/userinfo").json()
                print("Claims", claims)
            except Exception as e:
                print(e)
                raise falcon.HTTPFound(location='/login')

class Login:
    def on_get(self, req, resp):
        auth_url, state = oauth2_client.create_authorization_url(authorization_endpoint)
        r = requests.get(auth_url, allow_redirects=True)

        resp.set_cookie("oidc_state", state)
        resp.status = falcon.HTTP_302
        resp.set_header("Location", auth_url)

app = falcon.API(middleware=[AuthMiddleware(oauth2_client)])
app.add_route("/login", Login())
app.add_route("/api/hello", MyResource())