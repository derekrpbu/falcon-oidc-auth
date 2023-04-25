import falcon, json, requests, os
from dotenv import load_dotenv
from authlib.integrations.requests_client import OAuth2Session
from authlib.oidc.core import CodeIDToken
from authlib.jose import jwt

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

# define list of emails that have access to the app
email_list = ['derekrpbu@gmail.com']

# Create an OAuth2Session instance
oauth2_client = OAuth2Session(client_id, client_secret,redirect_uri=redirect_uri, scope=scope)      

jwks = {
  "keys": [
    {
      "kty": "RSA",
      "alg": "RS256",
      "e": "AQAB",
      "use": "sig",
      "n": "or83anRxFNTbjOy47m4SRDZQ7WpX_yjJdqN_LgNUBfbb_VnBwIUv_k4E1tXOE1yQC704YAT6JQ4AJtvLw598NxSuyXSvo-JCQ4pNugjVZ0w2MErJtARcxCu4LI6gsA_xSfSfuNVVSdrHqg8G-wsog0BS6N4M5IJtUlRR6UtjLaJxgqFGzV5sHWAfmpBekqCC5l19OXtE9J00r_Wjo4kfleonpVlEHszx5KUzShfGTGwgoeryNcp4yBULh8El8vt50a4SP_D74gCL5YINUl4E8hfQoqbPoxLj33oXYEvMKL34xYErEF5Tw39oAEfky3OgTXsCQvAp5il7HQjRY1JGow",
      "kid": "afc4fba6599ff5f63b72dc522428278682f3a7f1"
    },
    {
      "kid": "274052a2b6448745764e72c3590971d90cfb585a",
      "n": "w0PgyEXUS2Stec6a5nxWPg_39M9D2x-zQedSwBEYthJ9d4x5mf-h69H2u555VYI6TUA59I0cyFlEKzqMsednebyfNBld1QCjb1q9xxnRSS4YrFiQSdXSPiurlrEvrl_O04pLLx_yoXnCRSgO_Q21wj0QsfNZ5quMIcr72kmswOiqCdZOWgWKkYt_UKJKEIYLkRNykGQeA6rBIomsTqKJzkBY4ke7YAoBS2BsQgmPgOGD39EGp2sqDvbcLYME-2z8HEMNZIL78sBnCQ0ov3Mv5F1ds8FcBUp1qWgG-j81HMN0SkZPK5RCteP4eacOaXYS7FzNyXQYi_45PBQi9W0NHQ",
      "kty": "RSA",
      "alg": "RS256",
      "use": "sig",
      "e": "AQAB"
    }
  ]
}

class MyResource:
    def on_get(self, req, resp):
        content = {
            'name': 'Derek',
            'country': 'Costa Rica'
        }
        resp.body = json.dumps(content)
        resp.status = falcon.HTTP_200

class SearchApi:
    def on_get(self, req, resp):
        # Get query parameters from the request
        query_parameters = req.params

        # Use requests library to make a GET request to the public API
        response = requests.get('http://openlibrary.org/search.json?title=spiderman', params=query_parameters)

        # Set the response body to the data received from the API
        resp.body = response.text

class AuthMiddleware:
    def __init__(self, oauth2_client):
        self.oauth2_client = oauth2_client

    def process_request(self, req, resp):
        if req.path.startswith("/app"):
            if not validate_jwt(req.cookies.get("jwt")):
                try:
                    authorization_response = req.url
                    token = oauth2_client.fetch_token(token_endpoint, authorization_response=authorization_response, grant_type="authorization_code", expires_in=3600)
                    print("Token", token) 
                    resp.set_cookie("jwt", token["id_token"])
                    claims = oauth2_client.get("https://preprod.connect.kyndryl.net/oauth2/default/v1/userinfo").json()
                    print("Claims", claims)
                except Exception as e:
                    print(e)
                    raise falcon.HTTPFound(location='/login')
                if not validate_user(token["id_token"]):
                    print("User Unauthorized")
                    raise falcon.HTTPStatus(401, text="Unauthorized")              
            else:
                pass

def validate_jwt(token):
    try: 
        claims = jwt.decode(token, jwks, claims_cls=CodeIDToken)
        print(claims)
        claims.validate()
        if not validate_user(token):
            return False
    except Exception as e:
        print(e)
        return False
    
def validate_user(token):
    claims = jwt.decode(token, jwks, claims_cls=CodeIDToken)
    email = claims.get("email")
    print(email)
    if email in email_list:
        return True
    else: 
        return False

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
app.add_route("/api/search", SearchApi())