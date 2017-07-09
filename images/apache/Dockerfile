FROM boinc/server_apache:latest
#RUN sed -i -e 's/httpredir\.debian/de\.debian/g' /etc/apt/sources.list
RUN apt-get update && apt-get install python-mysqldb
RUN rm -rf /root/project/apps/* && rm -rf /root/project/templates/* 
COPY apps /root/project/apps/
COPY templates /root/project/templates/
COPY bin /root/project/bin/
#convert from dos 2 unix linebreaks
RUN cd /root/project/templates/ && for file in $(ls); do perl -pi -e 's/\r\n/\n/g' $file; done && chmod +x /root/project/bin/hashcat_assimilator.py
