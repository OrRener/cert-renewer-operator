FROM quay.io/centos/centos:stream9

RUN dnf install -y epel-release && \
    dnf install -y pdns pdns-backend-sqlite-4.8.4 sqlite && \
    dnf clean all

COPY pdns.conf /etc/pdns/pdns.conf

RUN mkdir /data && chown pdns:root /data && chmod 775 /data && mkdir /var/run/pdns && chown pdns:root /var/run/pdns 

COPY pdns.sqlite3 /etc/pdns

RUN chown pdns:root /etc/pdns/pdns.sqlite3 && chmod 664 /etc/pdns/pdns.sqlite3

USER pdns

WORKDIR /etc/pdns

CMD ["pdns_server", "--daemon=no", "--guardian=no"]
