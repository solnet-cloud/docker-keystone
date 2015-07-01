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
    apt-get install python python-jinja2 python-mysqldb keystone=$KS_PKG_NAME -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Prepare the various directories in /ks-data/
RUN \
    mkdir -p /ks-data/ && \
    mkdir -p /ks-templates/ && \
    mkdir -p /ks-templates/static
  
# Volumes

  
# Mount the configuration files

# Install the entry script
ADD scripts/entry.py /usr/local/bin/entry
RUN chmod +x /usr/local/bin/entry

# Define a working directory
WORKDIR /ks-data

# Define default command as entrypoint
ENTRYPOINT ["/usr/local/bin/entry"]

# Expose ports
