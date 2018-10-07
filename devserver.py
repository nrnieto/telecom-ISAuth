from ISAuth.app import *

if __name__ == '__main__':
    """
    Starts debug server
    """
    #context = ('./certs/wildcard_corp_cablevision.crt', './certs/wildcard_corp_cablevision.key')
    APP.run(debug=False, host='0.0.0.0', port=5000, ssl_context=None)
