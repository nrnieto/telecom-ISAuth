"""Flask main app"""

import uuid
from uuid import UUID
import json
import time
import logging
from flask import request, jsonify, Response
import requests
from requests.auth import HTTPBasicAuth
from requests import Session, ConnectionError, HTTPError, Timeout
from zeep.transports import Transport
from zeep import Client
import graypy
from ISAuth import APP
import os

#: Disable insecure idp certificate warning
requests.packages.urllib3.disable_warnings()

#: Load json config file
with open('./config/config.json', 'r') as config_file:
    CONFIG = json.load(config_file)

#: Sets Logger
LOGGER = logging.getLogger('ISAuth logger')
LOGGER.setLevel(logging.DEBUG)
HANDLER = graypy.GELFHandler(CONFIG["GRAYLOG_CONFIG"]["GRAYLOG_HOST"],
                             CONFIG["GRAYLOG_CONFIG"]["GRAYLOG_PORT"])
LOGGER.addHandler(HANDLER)

# stdout Logger

STDOUT_LOGGER = logging.getLogger("ISAuth stdout logger")
STDOUT_LOGGER.setLevel(logging.INFO)
STDOUT_LOGGER_HANDLER = logging.StreamHandler()
STDOUT_LOGGER_HANDLER.setLevel(logging.INFO)
STDOUT_LOGGER.addHandler(STDOUT_LOGGER_HANDLER)


@APP.route(CONFIG["APIDOC_ENDPOINT"], methods=['GET'])
def api_doc():
    """
    api-doc endpoint
    :return: json swagger
    :rtype: flask.Response
    """
    with open('./ISAuth/swagger.json', 'r') as swagger:
        return jsonify(json.load(swagger))


@APP.route(CONFIG["AUTHENTICATION_ENDPOINT"], methods=['POST'])
def authenticate():
    """
    Authentication endpoint
    :return: Response object
    :rtype: flask.Response
    """
    oauth_consumer_key = request.headers.get('OAuth-Consumer-Key')
    oauth_consumer_secret = request.headers.get('OAuth-Consumer-Secret')
    teco_uuid = request.headers.get('Teco-UUID')
    if teco_uuid and not valid_uuid4(teco_uuid) or not teco_uuid:
        teco_uuid = str(uuid.uuid4())
    try:
        request_body = request.get_json()
    #: Malformed json
    except Exception:
        log(teco_uuid, oauth_consumer_key, CONFIG["ERR_MSG"]["BAD_REQUEST"],
            CONFIG["AUTHENTICATION_ENDPOINT"])
        return Response(status=400, headers={"teco_uuid": teco_uuid})
    #: Bad keys
    try:
        username = request_body["username"]
        password = request_body["password"]
    except (KeyError, TypeError):
        log(teco_uuid, oauth_consumer_key, CONFIG["ERR_MSG"]["BAD_REQUEST"],
            CONFIG["AUTHENTICATION_ENDPOINT"])
        return Response(status=400, headers={"teco_uuid": teco_uuid})
    try:
        response = request_access_token(username,
                                        password,
                                        oauth_consumer_key,
                                        oauth_consumer_secret)
    #: Connection errors
    except (ConnectionError, Timeout, HTTPError) as err:
        log(teco_uuid, oauth_consumer_key,
            CONFIG["ERR_MSG"]["CONNECTION_ERROR"],
            CONFIG["AUTHENTICATION_ENDPOINT"])
        return Response(status=500, headers={"teco_uuid": teco_uuid})
    if response.status_code == 200:
        access_token = json.loads(response.text)["access_token"]
    #: IDP returns 400 at invalid password
    elif response.status_code == 400 or response.status_code == 401:
        log(teco_uuid,
            oauth_consumer_key,
            CONFIG["ERR_MSG"]["UNAUTHORIZED"],
            CONFIG["AUTHENTICATION_ENDPOINT"])
        return Response(status=401, headers={"teco_uuid": teco_uuid})
    else:
        log(teco_uuid,
            oauth_consumer_key,
            CONFIG["ERR_MSG"]["INTERNAL_SERVER_ERROR"],
            CONFIG["AUTHENTICATION_ENDPOINT"])
        return Response(status=500, headers={"teco_uuid": teco_uuid})
    log(teco_uuid, oauth_consumer_key,
        str(response.status_code),
        CONFIG["AUTHENTICATION_ENDPOINT"])
    response = jsonify(accessToken=access_token, jwt=get_jwt(access_token))
    response.headers["teco-uuid"] = teco_uuid
    return response


def request_access_token(username, password, oauth_consumer_key, oauth_consumer_secret):
    """
    Returns http response
    :param str username: The user to authenticate
    :param str password: The user's password to authenticate
    :param str oauth_consumer_key: oauth2 consumer key
    :param str oauth_consumer_secret: oauth2 consumer secret key
    :return: http response
    :rtype: flask.Response
    """
    try:
        response = requests.post(CONFIG["IS_CONFIG"]["IS_HOST"] +
                                 ':' + str(CONFIG["IS_CONFIG"]["IS_PORT"]) +
                                 CONFIG["IS_CONFIG"]["OAUTH_REQUEST_TOKEN_SERVICE"],
                                 headers={'Content-Type': 'application/x-www-form-urlencoded'},
                                 data=[('grant_type', 'password'),
                                       ('username', username),
                                       ('password', password)],
                                 verify=False,
                                 auth=(oauth_consumer_key, oauth_consumer_secret),
                                 timeout=CONFIG["REQUEST_ACCESS_TOKEN_TIMEOUT"])
    except ConnectionError as connection_error:
        raise connection_error
    except Timeout as timeout_error:
        raise timeout_error
    except HTTPError as http_error:
        raise http_error
    return response


@APP.route(CONFIG["VALIDATION_ENDPOINT"], methods=['POST'])
def validate():
    """
    Access token validation endpoint
    :return: Response object
    :rtype: flask.Response
    """
    teco_uuid = request.headers.get('Teco-UUID')
    if teco_uuid and not valid_uuid4(teco_uuid) or not teco_uuid:
        teco_uuid = str(uuid.uuid4())
    try:
        request_body = json.loads(request.data.decode('utf-8'))
        access_token = request_body["token"]
    except (KeyError, ValueError, TypeError):
        log(teco_uuid, None, CONFIG["ERR_MSG"]["BAD_REQUEST"], CONFIG["VALIDATION_ENDPOINT"])
        return Response(status=400, headers={"teco_uuid": teco_uuid})
    session = Session()
    session.auth = HTTPBasicAuth(CONFIG["IS_CONFIG"]["IS_USER"], CONFIG["IS_CONFIG"]["IS_PASSWORD"])
    session.verify = False
    try:
        client = Client(CONFIG["IS_CONFIG"]["IS_HOST"] +
                        ":" + str(CONFIG["IS_CONFIG"]["IS_PORT"]) +
                        CONFIG["IS_CONFIG"]["OAUTH2_TOKEN_VALIDATION_SERVICE"],
                        transport=Transport(session=session,
                                            timeout=CONFIG["VALIDATE_ACCESS_TOKEN_TIMEOUT"]))
    except ConnectionError:
        log(teco_uuid,
            None,
            CONFIG["ERR_MSG"]["CONNECTION_ERROR"],
            CONFIG["VALIDATION_ENDPOINT"])
        return Response(status=500, headers={"teco_uuid": teco_uuid})
    validation_req_dto = {'accessToken': {'identifier': access_token, 'tokenType': 'Bearer'},
                          'context': {},
                          'requiredClaimURIs': CONFIG["IS_CONFIG"]["REQUIRED_CLAIMS_URIS"]}
    try:
        obj = client.service.validate(validationReqDTO=validation_req_dto)
        session.close()
        if obj.valid: return Response(status=200, headers={"teco-uuid": teco_uuid})
    #: Bad idp response
    except Exception:
        log(teco_uuid,
            None,
            CONFIG["ERR_MSG"]["INTERNAL_SERVER_ERROR"],
            CONFIG["VALIDATION_ENDPOINT"])
        return Response(status=500, headers={"teco_uuid": teco_uuid})
    return Response(status=401, headers={"teco_uuid": teco_uuid})


@APP.route(CONFIG["REVOCATION_ENDPOINT"], methods=['POST'])
def revoke():
    """
    Access token revoke endpoint
    :return: Response object
    :rtype: flask.Response
    """
    oauth_consumer_key = request.headers.get('OAuth-Consumer-Key')
    oauth_consumer_secret = request.headers.get('OAuth-Consumer-Secret')
    teco_uuid = request.headers.get('Teco-UUID')
    if teco_uuid and not valid_uuid4(teco_uuid) or not teco_uuid:
        teco_uuid = str(uuid.uuid4())
    try:
        request_body = request.get_json()
        access_token = request_body["token"]
    except Exception:
        log(teco_uuid,
            oauth_consumer_key,
            CONFIG["ERR_MSG"]["BAD_REQUEST"],
            CONFIG["AUTHENTICATION_ENDPOINT"])
        return Response(status=400, headers={"teco_uuid": teco_uuid})
    try:
        response = revoke_token(access_token, oauth_consumer_key, oauth_consumer_secret)
    except ConnectionError:
        log(teco_uuid, oauth_consumer_key,
            CONFIG["ERR_MSG"]["CONNECTION_ERROR"],
            CONFIG["REVOCATION_ENDPOINT"])
        return Response(status=500, headers={"teco_uuid": teco_uuid})
    log(teco_uuid, oauth_consumer_key, str(response.status_code), CONFIG["REVOCATION_ENDPOINT"])
    return Response(status=response.status_code, headers={"teco_uuid": teco_uuid})


def get_jwt(access_token):
    """
    Receives session's access token, returns jwt
    :param str access_token: Session's access token
    :return: jwt
    :rtype: str
    """
    session = Session()
    session.auth = HTTPBasicAuth(CONFIG["IS_CONFIG"]["IS_USER"],
                                 CONFIG["IS_CONFIG"]["IS_PASSWORD"])
    session.verify = False
    client = Client(CONFIG["IS_CONFIG"]["IS_HOST"] +
                    ":" +
                    str(CONFIG["IS_CONFIG"]["IS_PORT"]) +
                    CONFIG["IS_CONFIG"]["OAUTH2_TOKEN_VALIDATION_SERVICE"],
                    transport=Transport(session=session))
    validation_req_dto = {'accessToken': {'identifier': access_token, 'tokenType': 'Bearer'},
                          'context': {},
                          'requiredClaimURIs': CONFIG["IS_CONFIG"]["REQUIRED_CLAIMS_URIS"]}
    obj = client.service.validate(validationReqDTO=validation_req_dto)
    session.close()
    return obj.authorizationContextToken.tokenString  # jwt


def log(teco_uuid, consumer, event, service):
    """
    Graylog logger
    :param teco_uuid: uuid
    :param consumer: consumer application
    :param event: event
    :param service: endpoint
    :return: None
    """
    LOGGER.debug({"teco_uuid": teco_uuid,
                  "oauth_consumer_key": consumer,
                  "event": event,
                  "timestamp": int(time.time()),
                  "service": os.environ["HOSTNAME"] + service})
    STDOUT_LOGGER.info({"teco_uuid": teco_uuid,
                       "oauth_consumer_key": consumer,
                       "event": event,
                       "timestamp": int(time.time()),
                       "service": os.environ["HOSTNAME"] + service})


def valid_uuid4(uuid_string):
    """
    Receives uuid str, returns bool
    :param uuid_string: uuid token
    :return: bool
    """
    try:
        UUID(uuid_string, version=4)
    except ValueError:
        return False
    return True


def revoke_token(access_token, oauth_consumer_key, oauth_consumer_secret):
    """
    Revoke access token
    :param access_token:
    :param oauth_consumer_key:
    :param oauth_consumer_secret:
    :return: response object
    :rtype: flask.Response
    """
    try:
        response = requests.post(CONFIG["IS_CONFIG"]["IS_HOST"] +
                                 ':' + str(CONFIG["IS_CONFIG"]["IS_PORT"]) +
                                 CONFIG["IS_CONFIG"]["OAUTH_REVOKE_TOKEN_SERVICE"],
                                 headers={'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8'},
                                 data=[('token', access_token),
                                       ('token_type_hint', 'access_token'),
                                       ('grant_type', 'password')],
                                 verify=False,
                                 auth=(oauth_consumer_key, oauth_consumer_secret),
                                 timeout=CONFIG["REVOKE_ACCESS_TOKEN_TIMEOUT"])
    except ConnectionError as connection_error:
        raise connection_error
    except Timeout as timeout_error:
        raise timeout_error
    except HTTPError as http_error:
        raise http_error
    return response


@APP.route(CONFIG["HEALTHCHECK_ENDPOINT"], methods=['GET'])
def health():
    """
    Health endpoint
    :return: json object
    :rtype: flask.Response
    """
    health_check = {"healthSummary": {"dependencies": []}}
    health_check["healthSummary"]["dependencies"].append(validate_token_health_check())
    health_check["healthSummary"]["dependencies"].append(request_token_health_check())
    health_check["healthSummary"]["dependencies"].append(revoke_token_health_check())
    health_check["healthSummary"]["result"] = {"healthy": request_token_health_check()["healthCheck"]["healthy"] and
                                                          validate_token_health_check()["healthCheck"]["healthy"] and
                                                          revoke_token_health_check()["healthCheck"]["healthy"],
                                               "description": CONFIG["HEALTH_CONFIG"]["OVERALL_HEALTHCHECK_DESCRIPTION"]
                                              }
    return jsonify(health_check)


def request_token_health_check():
    """
    request token health check
    :return: json object
    """
    dependency_healthcheck = {"name": CONFIG["HEALTH_CONFIG"]["REQUEST_TOKEN"]["NAME"],
                              "description": CONFIG["HEALTH_CONFIG"]["REQUEST_TOKEN"]["DESCRIPTION"],
                              "href": CONFIG["IS_CONFIG"]["IS_HOST"] +
                                      ":" +
                                      str(CONFIG["IS_CONFIG"]["IS_PORT"]) +
                                      CONFIG["IS_CONFIG"]["OAUTH_REQUEST_TOKEN_SERVICE"]
                             }
    try:
        request_token_response = requests.post(CONFIG["IS_CONFIG"]["IS_HOST"] +
                                               ':' + str(CONFIG["IS_CONFIG"]["IS_PORT"]) +
                                               CONFIG["IS_CONFIG"]["OAUTH_REQUEST_TOKEN_SERVICE"],
                                               headers={'Content-Type': 'application/x-www-form-urlencoded'},
                                               verify=False,
                                               timeout=CONFIG["REQUEST_ACCESS_TOKEN_TIMEOUT"])
        response_time = round(request_token_response.elapsed.total_seconds() * 1000, 2)
        if request_token_response.status_code == 400:  # expecting 400
            dependency_healthcheck["healthCheck"] = {"healthy": True,
                                                     "response_time": response_time,
                                                     "description": "POST"
                                                    }
        else:
            dependency_healthcheck["healthCheck"] = {"healthy": False,
                                                     "response_time": 0,
                                                     "description": request_token_response.status_code}
    except (ConnectionError, Timeout, HTTPError) as error:
        dependency_healthcheck["healthCheck"] = {"healthy": False,
                                                 "response_time": 0,
                                                 "description": str(error)}
    return dependency_healthcheck


def validate_token_health_check():
    """
    validate token health check
    :return: json object
    """
    dependency_healthcheck = {"name": CONFIG["HEALTH_CONFIG"]["VALIDATE_TOKEN"]["NAME"],
                              "description": CONFIG["HEALTH_CONFIG"]["VALIDATE_TOKEN"]["DESCRIPTION"],
                              "href": CONFIG["IS_CONFIG"]["IS_HOST"] +
                                      ":" +
                                      str(CONFIG["IS_CONFIG"]["IS_PORT"]) +
                                      CONFIG["IS_CONFIG"]["OAUTH2_TOKEN_VALIDATION_SERVICE"]
                             }
    try:
        validation_response = requests.get(CONFIG["IS_CONFIG"]["IS_HOST"] +
                                           ":" +
                                           str(CONFIG["IS_CONFIG"]["IS_PORT"]) +
                                           CONFIG["IS_CONFIG"]["OAUTH2_TOKEN_VALIDATION_SERVICE"],
                                           verify=False, timeout=3)
        response_time = round(validation_response.elapsed.total_seconds() * 1000, 2)
        if validation_response.status_code == 200:
            dependency_healthcheck["healthCheck"] = {"healthy": True,
                                                     "response_time": response_time,
                                                     "description": "GET"
                                                    }
        else:
            dependency_healthcheck["healthCheck"] = {"healthy": False,
                                                     "response_time": response_time,
                                                     "description": str(validation_response.status_code)
                                                    }
    except ConnectionError as connection_error:
        dependency_healthcheck["healthCheck"] = {"healthy": False,
                                                 "response_time": 0,
                                                 "description": str(connection_error)}
    return dependency_healthcheck


def revoke_token_health_check():
    """
    revoke token health check
    :return: json object
    """
    dependency_healthcheck = {"name": CONFIG["HEALTH_CONFIG"]["REVOKE_TOKEN"]["NAME"],
                              "description": CONFIG["HEALTH_CONFIG"]["REVOKE_TOKEN"]["DESCRIPTION"],
                              "href": CONFIG["IS_CONFIG"]["IS_HOST"] +
                                      ":" +
                                      str(CONFIG["IS_CONFIG"]["IS_PORT"]) +
                                      CONFIG["IS_CONFIG"]["OAUTH_REVOKE_TOKEN_SERVICE"]
                             }
    try:
        revoke_response = revoke_token(CONFIG["EXPIRED_VALID_TOKEN"],
                                       oauth_consumer_key=CONFIG["OAUTH_CONSUMER_KEY"],
                                       oauth_consumer_secret=CONFIG["OAUTH_CONSUMER_SECRET"])
        response_time = round(revoke_response.elapsed.total_seconds() * 1000, 2)
        if revoke_response.status_code == 200:
            dependency_healthcheck["healthCheck"] = {"healthy": True,
                                                     "response_time": response_time,
                                                     "description": "POST"
                                                    }
        else:
            dependency_healthcheck["healthCheck"] = {"healthy": False,
                                                     "response_time": response_time,
                                                     "description": str(revoke_response.status_code)
                                                    }
    except (ConnectionError, Timeout, HTTPError) as error:
        dependency_healthcheck["healthCheck"] = {"healthy": False,
                                                 "response_time": 0,
                                                 "description": str(error)}
    return dependency_healthcheck


@APP.errorhandler(404)
def page_not_found(e):
    """
    Page not found error handler
    :param e:
    :return: Response object
    :rtype: flask.Response
    """
    teco_uuid = request.headers.get('teco-uuid')
    oauth_consumer_key = request.headers.get('OAuth-Consumer-Key')
    if teco_uuid and not valid_uuid4(teco_uuid) or not teco_uuid:
        teco_uuid = str(uuid.uuid4())
    log(teco_uuid, oauth_consumer_key, CONFIG["ERR_MSG"]["NOT_FOUND"], "404")
    return Response(status=404, headers={"teco-uuid": teco_uuid})


@APP.errorhandler(500)
def internal_server_error(e):
    """
    Internal server error handler
    :param e:
    :return: Response object
    :rtype: flask.Response
    """
    teco_uuid = request.headers.get('teco-uuid')
    oauth_consumer_key = request.headers.get('OAuth-Consumer-Key')
    if teco_uuid and not valid_uuid4(teco_uuid) or not teco_uuid:
        teco_uuid = str(uuid.uuid4())
    log(teco_uuid, oauth_consumer_key, CONFIG["ERR_MSG"]["INTERNAL_SERVER_ERROR"], "500")
    return Response(status=500, headers={"teco-uuid": teco_uuid})
