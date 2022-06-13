FROM ubuntu:20.04

RUN apt-get update && apt-get install -y python3 python3-pip
RUN pwd && ls && echo "GITHUB_WORKSPACE=$GITHUB_WORKSPACE"
RUN ls -l /home
RUN ls -l /home/runner
RUN ls -l /home/runner/work
RUN ls -l /home/runner/work/xnolib
RUN ls -l /home/runner/work/xnolib/xnolib
RUN pip3 install -r /home/runner/work/xnolib/xnolib/requirements.txt

ADD entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
