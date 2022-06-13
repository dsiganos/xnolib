FROM ubuntu:20.04

RUN apt-get update && apt-get install -y python3 python3-pip
RUN pwd && ls && echo "GITHUB_WORKSPACE=$GITHUB_WORKSPACE"
RUN env
RUN pip3 install -r $GITHUB_WORKSPACE/requirements.txt

ADD entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
