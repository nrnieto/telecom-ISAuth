FROM registry.access.redhat.com/rhscl/python-36-rhel7

ENV PYTHONPATH /src

ADD ISAuth /src/ISAuth
ADD tests /src/tests
ADD gunicorn.sh /src
ADD certs /src/certs
ADD config /src/config

WORKDIR /src

RUN pip3 install -r ./ISAuth/requirements.txt
RUN python3 /src/tests/unit_tests.py -v
RUN pylint /src/ISAuth/app.py --errors-only -s y -r y

CMD "./gunicorn.sh"