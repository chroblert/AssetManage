FROM python:3.6-buster
COPY . /root/AssetManage/
RUN cd /root/AssetManage/Util
WORKDIR /root/AssetManage/Util
RUN tar -xzvf Django-3.0.4.tar.gz
RUN rm -f Django-3.0.4.tar.gz
RUN cd ./Django-3.0.4
WORKDIR ./Django-3.0.4
RUN python setup.py install
RUN cd /root/AssetManage
WORKDIR /root/AssetManage
RUN python -m pip install -r requirements.txt
EXPOSE 8000
RUN apt-get update
RUN apt-get install git gcc make libpcap-dev clang -y
RUN cd ./Util/masscan-1.0.5/
WORKDIR ./Util/masscan-1.0.5/
RUN make
RUN ln -s /root/AssetManage/Util/masscan-1.0.5/bin/masscan /usr/local/bin/masscan
RUN apt-get install openssl libssl-dev libssh2-1-dev build-essential -y
RUN cd ../nmap-7.80/
WORKDIR ../nmap-7.80/
RUN chmod +x ./* && ./configure && make && make install
RUN cd /root/AssetManage/
WORKDIR /root/AssetManage/
# tar xf nmap-7.80.tar.bz2 && cd nmap-7.80 && chmod +x ./* && ./configure && make && make install
RUN python manage.py makemigrations
RUN python manage.py migrate
CMD ["python","manage.py","runserver","0.0.0.0:8000"]