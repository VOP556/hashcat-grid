FROM boinc/server_makeproject:latest
RUN rm -f /root/project/html/project/project.inc
ADD project.inc /root/project/html/project/project.inc
ADD project.xml /root/project/
ADD config.xml /root/project/
RUN sed -i -e 's/options\.LAZY\_LOOKUPS\ \=\ True/options\.LAZY\_LOOKUPS\ \=\ False/g' /root/project/py/Boinc/db_base.py
ADD py/Boinc/database.py /root/project/py/Boinc/
ADD schema.sql /root/boinc/db/

#RUN /root/project/bin/xadd
