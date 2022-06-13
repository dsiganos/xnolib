FROM ubuntu:20.04

RUN apt-get update && apt-get install -y python3 python3-pip
RUN pip3 install -r requirements.txt

ADD entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
