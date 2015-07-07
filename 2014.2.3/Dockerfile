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
# Version 2014.2.3
#       - First version

# Set the Keystone version and other enviroment variables
ENV KS_PKG_NAME 1:2014.2.3-0ubuntu1~cloud0

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

  
# Mount the configuration files
ADD templates/keystone.conf /ks-templates/keystone.conf
ADD templates/keystone-paste.ini /ks-templates/keystone-paste.ini

# Mount the static configuration files
ADD templates/static/logging.conf /etc/keystone/logging.conf
ADD templates/static/policy.json /etc/keystone/policy.json

# Install the entry script
ADD scripts/entry.py /usr/local/bin/entry
RUN chmod +x /usr/local/bin/entry

# Define a working directory
WORKDIR /ks-data

# Define default command as entrypoint
ENTRYPOINT ["/usr/local/bin/entry"]

# Expose ports
# Expose 5000  : Public API Port
# Expose 35357 : Admin API Port
EXPOSE 5000  
EXPOSE 35357 