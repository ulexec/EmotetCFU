docker build -t emotet_cfu . 
docker run emotet_cfu /bin/bash -c "python docker-entrypoint.py; /bin/bash"
sudo docker cp $(sudo docker ps -l | awk -F 'emotet_cfu' '{print $1}' |  awk -F 'CONTAINER' '{print $1}' | awk -F ' ' '{print $1}'):/EmotetCFU/emotet.unp1.exe ./emotet.unp1.exe.d
sudo docker stop $(sudo docker ps -l | awk -F 'emotet_cfu' '{print $1}' |  awk -F 'CONTAINER' '{print $1}' | awk -F ' ' '{print $1}')
