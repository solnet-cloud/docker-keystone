# Keystone Docker
# Solnet Solutions
# Version: 2014.2.3

# Pull base image (Ubuntu)
FROM ubuntu:14.04

# Build Instructions:
# When building use the following flags:
#      --tag="keystone:2014.2.3" 

# Run Instructions:
# When running use the following flags:
#      --restart=on-failure --log-driver=syslog
# The following command line arguments are supported.

# Information
MAINTAINER Taylor Bertie <taylor.bertie@solnet.co.nz>
LABEL Description="This image is used to stand up a Keystone instance under httpd." Version="2014.2.3"

# Patch notes:
# Version 2014.2.3-r1
#       - Moved to an Apache HTTPD based version
# Version 2014.2.3
#       - First version

# Set the Keystone version and other enviroment variables
ENV KS_PKG_NAME 1:2014.2.3-0ubuntu1~cloud0
ENV APACHE_RUN_USER www-data
ENV APACHE_RUN_GROUP www-data
ENV APACHE_LOG_DIR /var/log/apache2
ENV APACHE_PID_FILE /var/run/apache2.pid
ENV APACHE_RUN_DIR /var/run/apache2
ENV APACHE_LOCK_DIR /var/lock/apache2
ENV APACHE_SERVERADMIN admin@localhost
ENV APACHE_SERVERNAME localhost
ENV APACHE_SERVERALIAS docker.localhost
ENV APACHE_DOCUMENTROOT /var/www


# Install the cloud keyring
RUN \
    apt-get update && \
    apt-get install ubuntu-cloud-keyring -y && \
    echo "deb http://ubuntu-cloud.archive.canonical.com/ubuntu" \
        "trusty-updates/juno main" > /etc/apt/sources.list.d/cloudarchive-juno.list && \
    rm -fr /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Install the required packages
RUN \
    apt-get update && \
    apt-get install python python-jinja2 python-mysqldb apache2 libapache2-mod-wsgi keystone=$KS_PKG_NAME -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*
    
# NB: Installing Apache2 so we can move to a mod_wsgi implementation in future as in the M-release the inbuilt web
#       server will not longer be supported by Keystone

# Prepare the various directories in /ks-data/
RUN \
    mkdir -p /ks-data/ && \
    mkdir -p /ks-data/ssl/ && \
    mkdir -p /ks-templates/ && \
    mkdir -p /ks-templates/static

# Volumes
# None
  
# Mount the configuration files
ADD templates/keystone.conf /ks-templates/keystone.conf
ADD templates/keystone-paste.ini /ks-templates/keystone-paste.ini

# Mount the static configuration files
ADD templates/static/logging.conf /etc/keystone/logging.conf
ADD templates/static/policy.json /etc/keystone/policy.json
ADD templates/static/wsgi-keystone.conf /etc/apache2/sites-available/wsgi-keystone.conf


# Install the entry script
ADD scripts/keystone.py /usr/local/bin/keystone.py
ADD scripts/entry.py /usr/local/bin/entry
RUN \
    chmod +x /usr/local/bin/entry && \
    chmod +x /usr/local/bin/keystone.py

# Define a working directory
WORKDIR /ks-data

# Setup Apache2 Enviroment
RUN \
    rm /etc/apache2/sites-enabled/000-default.conf && \
    ln -s /etc/apache2/sites-available/wsgi-keystone.conf /etc/apache2/sites-enabled/wsgi-keystone.conf && \
    mkdir -p /var/www/cgi-bin/keystone/ && \
    ln -s /usr/local/bin/keystone.py /var/www/cgi-bin/keystone/main && \
    ln -s /usr/local/bin/keystone.py /var/www/cgi-bin/keystone/admin

# Define default command as entrypoint
ENTRYPOINT ["/usr/local/bin/entry"]

# Expose ports
# Expose 5000  : Public API Port
# Expose 35357 : Admin API Port
EXPOSE 5000  
EXPOSE 35357 