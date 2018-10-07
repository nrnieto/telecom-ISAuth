*
Authenticate LDAP users over WSO2 IS

Docker commands:

    docker build -t sr-docker-xp01.corp.cablevision.com.ar/is-auth:1.0 .

    docker run -d --name=ISAuth -e "HOSTNAME=$(cat /etc/hostname)" -m=2048m --dns=192.168.182.46 --dns=192.168.5.11 --dns-search=corp.cablevision.com.ar -p 5000:5000 sr-docker-xp01.corp.cablevision.com.ar/is-auth:1.0
    
    docker stop ISAuth
    
    docker rm ISAuth
    
Run App:

    ./gunicorn.sh    
    
gevent 1.3.0 issue:
    
    https://github.com/gevent/gevent/issues/1016    
