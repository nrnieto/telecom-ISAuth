import unittest
import json
import requests
import logging
import ISAuth
from ISAuth.app import APP

requests.packages.urllib3.disable_warnings()


LOGGER = logging.getLogger('ISAuth test logger')
LOGGER.setLevel(logging.DEBUG)
CONSOLE_HANDLER = logging.StreamHandler()
LOGGER.addHandler(CONSOLE_HANDLER)

#: Load json config file
with open('./config/config.json', 'r') as config_file:
    CONFIG = json.load(config_file)


class ISAuthUnitTests(unittest.TestCase):
    """
    Unit Test Object
    """
    def setUp(self):
        """"""
        self.app = ISAuth.app.APP.test_client()
        self.oauth_consumer_key = CONFIG["OAUTH_CONSUMER_KEY"]
        self.oauth_consumer_secret = CONFIG["OAUTH_CONSUMER_SECRET"]
        self.post_headers = {"oauth_consumer_key": CONFIG["OAUTH_CONSUMER_KEY"],
                             "oauth_consumer_secret": CONFIG["OAUTH_CONSUMER_SECRET"]
                             }
        self.post_content_type = "application/json"

    def test_authenticate_valid_user(self):
        """"""
        response = self.app.post('/authenticate',
                                 headers=self.post_headers,
                                 content_type=self.post_content_type,
                                 data=json.dumps({"username": "admin",
                                                  "password": "admin"})
                                 )
        self.assertEqual(response.status_code, 200)

    def test_authenticate_invalid_user(self):
        """"""
        response = self.app.post('/authenticate',
                                 headers=self.post_headers,
                                 content_type=self.post_content_type,
                                 data=json.dumps({"username": "abd123",
                                                  "password": "admin"})
                                 )
        self.assertEqual(response.status_code, 401)

    def test_authenticate_invalid_password(self):
        """"""
        response = self.app.post('/authenticate',
                                 headers=self.post_headers,
                                 content_type=self.post_content_type,
                                 data=json.dumps({"username": "admin",
                                                  "password": 200})
                                 )
        self.assertEqual(response.status_code, 401)

    def test_authenticate_invalid_content_type(self):
        """"""
        response = self.app.post('/authenticate',
                                 headers=self.post_headers,
                                 content_type="application/xml",
                                 data=json.dumps({"username": "admin",
                                                  "password": "admin"})
                                 )
        self.assertEqual(response.status_code, 400)

    def test_authenticate_invalid_endpoint(self):
        """"""
        response = self.app.post('/???',
                                 headers=self.post_headers,
                                 content_type=self.post_content_type,
                                 data=json.dumps({"username": "admin",
                                                  "password": "admin"})
                                 )
        self.assertEqual(response.status_code, 404)

    def test_authenticate_invalid_consumer_key(self):
        """"""
        response = self.app.post('/authenticate',
                                 headers={"oauth_consumer_key": '???',
                                          "oauth_consumer_secret": self.oauth_consumer_secret
                                          },
                                 content_type=self.post_content_type,
                                 data=json.dumps({"username": "admin",
                                                  "password": "admin"})
                                 )
        self.assertEqual(response.status_code, 401)

    def test_authenticate_invalid_consumer_secret(self):
        """"""
        response = self.app.post('/authenticate',
                                 headers={"oauth_consumer_key": self.oauth_consumer_key,
                                          "oauth_consumer_secret": '???'
                                          },
                                 content_type=self.post_content_type,
                                 data=json.dumps({"username": "admin",
                                                  "password": "admin"})
                                 )
        self.assertEqual(response.status_code, 401)

    def test_authenticate_invalid_json(self):
        """"""
        response = self.app.post('/authenticate',
                                 headers=self.post_headers,
                                 content_type=self.post_content_type,
                                 data=str(["username", "abd123",
                                          "password", "admin"])
                                 )
        self.assertEqual(response.status_code, 400)

    def test_authenticate_teco_valid_uuid_header(self):
        """"""
        response = self.app.post('/authenticate',
                                 headers={"oauth_consumer_key": self.oauth_consumer_key,
                                          "oauth_consumer_secret": self.oauth_consumer_secret,
                                          "teco-uuid": "2b6abbe9-97f2-4260-bd11-87d9350831c3"
                                          },
                                 content_type=self.post_content_type,
                                 data=json.dumps({"username": "admin",
                                                  "password": "admin"})
                                 )
        self.assertEqual(response.status_code, 200)

    def test_authenticate_teco_invalid_uuid_header(self):
        """"""
        response = self.app.post('/authenticate',
                                 headers={"oauth_consumer_key": self.oauth_consumer_key,
                                          "oauth_consumer_secret": self.oauth_consumer_secret,
                                          "teco-uuid": "???"
                                          },
                                 content_type=self.post_content_type,
                                 data=json.dumps({"username": "admin",
                                                  "password": "admin"})
                                 )
        self.assertEqual(response.status_code, 200)

    def test_validate_valid_token(self):
        """"""
        authenticate_response = self.app.post('/authenticate',
                                              headers={"oauth_consumer_key": self.oauth_consumer_key,
                                                       "oauth_consumer_secret": self.oauth_consumer_secret,
                                                       },
                                              content_type=self.post_content_type,
                                              data=json.dumps({"username": "admin",
                                                              "password": "admin"})
                                              )
        access_token = json.loads(authenticate_response.data.decode("utf-8"))["accessToken"]
        validate_response = self.app.post('/validate',
                                          headers={"teco-uuid": "2b6abbe9-97f2-4260-bd11-87d9350831c3"},
                                          content_type=self.post_content_type,
                                          data=json.dumps({"token": access_token})
                                          )
        self.assertEqual(validate_response.status_code, 200)

    def test_validate_invalid_token(self):
        """"""
        response = self.app.post('/validate',
                                 headers={"teco-uuid": "2b6abbe9-97f2-4260-bd11-87d9350831c3"},
                                 content_type=self.post_content_type,
                                 data=json.dumps({"token": "???"})
                                 )
        self.assertEqual(response.status_code, 401)

    def test_validate_expired_token(self):
        """"""
        response = self.app.post('/validate',
                                 headers={"teco-uuid": "2b6abbe9-97f2-4260-bd11-87d9350831c3"},
                                 content_type=self.post_content_type,
                                 data=json.dumps({"token": "135f4b33ccae22de69c5b7daf9571a00"})
                                 )
        self.assertEqual(response.status_code, 401)

    def test_validate_invalid_json(self):
        """"""
        response = self.app.post('/validate',
                                 headers={"teco-uuid": "2b6abbe9-97f2-4260-bd11-87d9350831c3"},
                                 content_type=self.post_content_type,
                                 data=json.dumps(str(["token", "???"]))
                                 )
        self.assertEqual(response.status_code, 400)

    def test_validate_invalid_uuid_header(self):
        """"""
        authenticate_response = self.app.post('/authenticate',
                                              headers={"oauth_consumer_key": self.oauth_consumer_key,
                                                       "oauth_consumer_secret": self.oauth_consumer_secret,
                                                       },
                                              content_type=self.post_content_type,
                                              data=json.dumps({"username": "admin",
                                                              "password": "admin"})
                                              )
        access_token = json.loads(authenticate_response.data.decode("utf-8"))["accessToken"]
        response = self.app.post('/validate',
                                 headers={"teco-uuid": "???"},
                                 content_type=self.post_content_type,
                                 data=json.dumps({"token": access_token})
                                 )
        self.assertEqual(response.status_code, 200)

    def test_revoke_valid_token(self):
        """"""
        authenticate_response = self.app.post('/authenticate',
                                              headers={"oauth_consumer_key": self.oauth_consumer_key,
                                                       "oauth_consumer_secret": self.oauth_consumer_secret,
                                                       },
                                              content_type=self.post_content_type,
                                              data=json.dumps({"username": "admin",
                                                              "password": "admin"})
                                              )
        access_token = authenticate_response.data.decode("utf-8")
        response = self.app.post('/revoke',
                                 headers=self.post_headers,
                                 content_type=self.post_content_type,
                                 data=json.dumps({"token": access_token})
                                 )
        self.assertEqual(response.status_code, 200)

    def test_revoke_invalid_json(self):
        """"""
        response = self.app.post('/revoke',
                                 headers=self.post_headers,
                                 content_type=self.post_content_type,
                                 data=json.dumps(str({"token": "???"}))
                                 )
        self.assertEqual(response.status_code, 400)

    def test_revoke_invalid_consumer_key(self):
        """"""
        authenticate_response = self.app.post('/authenticate',
                                              headers={"oauth_consumer_key": self.oauth_consumer_key,
                                                       "oauth_consumer_secret": self.oauth_consumer_secret,
                                                       },
                                              content_type=self.post_content_type,
                                              data=json.dumps({"username": "admin",
                                                              "password": "admin"})
                                              )
        access_token = json.loads(authenticate_response.data.decode("utf-8"))["accessToken"]
        response = self.app.post('/revoke',
                                 headers={"oauth_consumer_key": "???",
                                          "oauth_consumer_secret": self.oauth_consumer_secret,
                                          },
                                 content_type=self.post_content_type,
                                 data=json.dumps({"token": access_token})
                                 )
        self.assertEqual(response.status_code, 401)

    def test_revoke_invalid_consumer_secret(self):
        """"""
        authenticate_response = self.app.post('/authenticate',
                                              headers=self.post_headers,
                                              content_type=self.post_content_type,
                                              data=json.dumps({"username": "admin",
                                                              "password": "admin"})
                                              )
        access_token = json.loads(authenticate_response.data.decode("utf-8"))["accessToken"]
        response = self.app.post('/revoke',
                                 headers={"oauth_consumer_key": self.oauth_consumer_key,
                                          "oauth_consumer_secret": "???",
                                          },
                                 content_type=self.post_content_type,
                                 data=json.dumps({"token": access_token})
                                 )
        self.assertEqual(response.status_code, 401)


if __name__ == '__main__':
    unittest.main()
