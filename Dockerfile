from ubuntu:18.04
RUN apt-get update -y && \
    apt-get install -y python git build-essential python-pip libpython-dev unzip

# Install radare2
RUN git clone http://github.com/radare/radare2 /opt/radare2
RUN cd /opt/radare2/; sys/install.sh; cd -
RUN pip install r2pipe 

# Create Working directory
RUN mkdir ./EmotetCFU
COPY ./emotet_cff_deobfuscate ./EmotetCFU/emotet_cff_deobfuscate
COPY ./samples.zip ./EmotetCFU/samples.zip
COPY ./requirements.txt ./EmotetCFU/requirements.txt 

WORKDIR ./EmotetCFU
RUN python -m pip install -r ./requirements.txt
ENV PYTHONUNBUFFERED=1
COPY ./docker-entrypoint.sh ./docker-entrypoint.sh
RUN chmod +x ./docker-entrypoint.sh
ENTRYPOINT ["./docker-entrypoint.sh"]
