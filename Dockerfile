FROM python:3.6-slim
# RUN python -m pip install Django==3.0.4
# WORKDIR ./
# wget https://www.djangoproject.com/download/3.0.4/tarball/ -O Django-3.0.4.tar.gz
# COPY Django-3.0.4.tar.gz /tmp/
# COPY AssetManage /root/
COPY . /root/AssetManage/
RUN cd /root/AssetManage/Util
WORKDIR /root/AssetManage/Util
RUN tar -xzvf Django-3.0.4.tar.gz
RUN rm -f Django-3.0.4.tar.gz
RUN cd ./Django-3.0.4
RUN python setup.py install
RUN cd /root/AssetManage
WORKDIR /root/AssetManage
#RUN python -m pip install -r requirements.txt
EXPOSE 8000
CMD ["python","manage.py","runserver","0.0.0.0:8000"]