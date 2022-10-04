FROM python:3.9

RUN apt-get update -y && \
    apt-get install -y default-libmysqlclient-dev libffi-dev

# We copy just the requirements.txt first to leverage Docker cache
ADD ./requirements.txt requirements.txt

COPY . .

RUN pip3 install -r requirements.txt

COPY . .