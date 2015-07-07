#!/usr/bin/env python
# This script takes the first command line argument and checks if it points to a valid elasticsearch cluster, and then
# starts up kibana. 

########################################################################################################################
# LIBRARY IMPORT                                                                                                       #
########################################################################################################################
# Import required libaries
import sys,os,pwd,grp   # OS Libraries
import argparse         # Parse Arguments
from subprocess import Popen, PIPE, STDOUT, check_call, CalledProcessError
                        # Open up a process

# Important required templating libarires
from jinja2 import Environment as TemplateEnvironment, \
                   FileSystemLoader, Template
                        # Import the jinja2 libaries required by this script
from jinja2.exceptions import TemplateNotFound
                        # Import any exceptions that are caught by the Templates section

# Specific to to this script

# Variables/Consts
ssl_path = '/ks-data/ssl/'

########################################################################################################################
# ARGUMENT PARSER                                                                                                      #
# This is where you put the Argument Parser lines                                                                      #
########################################################################################################################
argparser = argparse.ArgumentParser(description='Run a docker container containing a Keystone Instance')

argparser.add_argument('--adm-token','-t',
                       action='store',
                       help='Enables the adminstrative token')
argparser.add_argument('--debug','-d',       
                       action='store_true',
                       help='Turns on debug logging')
argparser.add_argument('--notify-topic','-n',
                       action='store',
                       help='The notify topic to use (Default: notifications)')
argparser.add_argument('--token-expire','-e',
                       action='store',
                       type=int,
                       help='The token expire period to use in seconds (Default: 3600)')
argparser.add_argument('--default-domain','-D',
                       action='store',
                       help='The default to domain for v2 clients to use (Default: default)')
argparser.add_argument('--rabbit-solo',
                       action='store_true',
                       help='Connect to a solo instance of RabbitMQ rather than a list of cluter nodes')
argparser.add_argument('--rabbit-port',
                       action='store',
                       type=int,
                       help='The port you should use to connect to RabbitMQ (Default: 5672)')
argparser.add_argument('--db-user',
                       action='store',
                       help='The user you should use to connect to MySQL (Default: keystone)')
argparser.add_argument('--db-name',
                       action='store',
                       help='The database name you should connect to  (Default: keystone)')
argparser.add_argument('db_host',
                       action='store',
                       help='The host or IP to connect to for MySQL')
argparser.add_argument('db_pass',
                       action='store',
                       help='The password for MySQL')
argparser.add_argument('rabbit_userid',
                       action='store',
                       help='UserID for RabbitMQ')
argparser.add_argument('rabbit_pass',
                       action='store',
                       help='Password for RabbitMQ')
argparser.add_argument('rabbit_hosts',
                       action='store',
                       nargs='+',
                       help='The rabbit MQ (hosts) keystone should connect to')


try:
    args = argparser.parse_args()
except SystemExit:
    sys.exit(0) # This should be a return 0 to prevent the container from restarting
    
########################################################################################################################
# ARGUMENT VERIRIFCATION                                                                                               #
# This is where you put any logic to verify the arguments, and failure messages                                        #
########################################################################################################################
# Check the admin token is a hexidecimal string
if args.adm_token is not None:
    pass




########################################################################################################################
# TEMPLATES                                                                                                            #
# This is where you manage any templates                                                                               #
########################################################################################################################
# Configuration Location goes here
template_location = '/ks-templates'

# Create the template list
template_list = {}

# Templates go here
### keystone.conf ###
template_name = 'keystone.conf'
template_dict = { 'context' : { # Subsitutions to be performed
                                'admin_token'      : args.adm_token if args.adm_token is not None else None,
                                'debug'            : args.debug,
                                'notify_topic'     : args.notify_topic if args.notify_topic is not None else 'notifications',
                                'rabbit_ha'        : not args.rabbit_solo,
                                'rabbit_hosts'     : ' '.join(args.rabbit_hosts),
                                'rabbit_port'      : args.rabbit_port if args.rabbit_port is not None else 5672,
                                'rabbit_userid'    : args.rabbit_userid,
                                'rabbit_pass'      : args.rabbit_pass,
                                'rabbit_ssl'       : False, #args.rabbit_ssl, #Not enabled yet
                                'rabbit_ca_certs'  : None, #args.rabbit_ca_certs if args.rabbit_ca_certs is not None else None,
                                'rabbit_ssl_key'   : None, #args.rabbit_ssl_key if args.rabbit_ssl_key is not None else None,
                                'rabbit_ssl_cert'  : None, #args.rabbit_ssl_cert if args.rabbit_ssl_cert is not None else None,                                
                                'keystone_db_user' : args.db_user if args.db_user is not None else 'keystone',
                                'keystone_db_pass' : args.db_pass,
                                'keystone_db_host' : args.db_host,
                                'keystone_db_name' : args.db_name if args.db_name is not None else 'keystone',
                                'default_domain'   : args.default_domain if args.default_domain is not None else 'default',
                                'token_expire'     : args.token_expire if args.token_expire is not None else 3600,
                              },
                  'path'    : '/etc/keystone/keystone.conf',
                  'user'    : 'root',
                  'group'   : 'root',
                  'mode'    : 0644 }
template_list[template_name] = template_dict

### keystone-paste.ini ###
template_name = 'keystone-paste.ini'
template_dict = { 'context' : { # Subsitutions to be performed
                                'admin_token'      : args.adm_token if args.adm_token is not None else None,
                              },
                  'path'    : '/etc/keystone/keystone-paste.ini',
                  'user'    : 'root',
                  'group'   : 'root',
                  'mode'    : 0644 }
template_list[template_name] = template_dict

# Load in the files from the folder
template_loader = FileSystemLoader(template_location)
template_env = TemplateEnvironment(loader=template_loader,
                                   lstrip_blocks=True,
                                   trim_blocks=True,
                                   keep_trailing_newline=True)

# Load in expected templates
for template_item in template_list:
    # Attempt to load the template
    try:
        template_list[template_item]['template'] = template_env.get_template(template_item)
    except TemplateNotFound as e:
        errormsg = "The template file %s was not found in %s (returned %s)," % (template_item, template_location, e)
        errormsg += " terminating..."
        print errormsg
        sys.exit(0) # This should be a return 0 to prevent the container from restarting

    # Attempt to open the file for writing
    try:
        template_list[template_item]['file'] = open(template_list[template_item]['path'],'w')
    except IOError as e:
        errormsg = "The file %s could not be opened for writing for template" % template_list[template_item]['path']
        errormsg += " %s (returned %s), terminating..." % template_item, e
        print errormsg
        sys.exit(0) # This should be a return 0 to prevent the container from restart
    
    # Stream
    try:
        template_list[template_item]['render'] = template_list[template_item]['template'].\
                                             render(template_list[template_item]['context'])
    
        # Submit to file
        template_list[template_item]['file'].write(template_list[template_item]['render'].encode('utf8'))
        template_list[template_item]['file'].close()
    except:
        e = sys.exc_info()[0]
        print "Unrecognised exception occured, was unable to create template (returned %s), terminating..." % e
        sys.exit(0) # This should be a return 0 to prevent the container from restarting.


    # Change owner and group
    try:
        template_list[template_item]['uid'] = pwd.getpwnam(template_list[template_item]['user']).pw_uid
    except KeyError as e:
        errormsg = "The user %s does not exist for template %s" % template_list[template_item]['user'], template_item
        errormsg += "(returned %s), terminating..." % e
        print errormsg
        sys.exit(0) # This should be a return 0 to prevent the container from restarting

    try:
        template_list[template_item]['gid'] = grp.getgrnam(template_list[template_item]['group']).gr_gid
    except KeyError as e:
        errormsg = "The group %s does not exist for template %s" % template_list[template_item]['group'], template_item
        errormsg += "(returned %s), terminating..." % e
        print errormsg
        sys.exit(0) # This should be a return 0 to prevent the container from restarting

    try:
        os.chown(template_list[template_item]['path'],
                 template_list[template_item]['uid'],
                 template_list[template_item]['gid'])
    except OSError as e:
        errormsg = "The file %s could not be chowned for template" % template_list[template_item]['path']
        errormsg += " %s (returned %s), terminating..." % template_item, e
        print errormsg
        sys.exit(0) # This should be a return 0 to prevent the container from restarting

    # Change premisions
    try:
        os.chmod(template_list[template_item]['path'],
                 template_list[template_item]['mode'])
    except OSError as e:
        errormsg = "The file %s could not be chmoded for template" % template_list[template_item]['path']
        errormsg += " %s (returned %s), terminating..." % template_item, e
        print errormsg
        sys.exit(0) # This should be a return 0 to prevent the container from restarting

########################################################################################################################
# SPAWN CHILD                                                                                                          #
########################################################################################################################
# Flush anything on the buffer
sys.stdout.flush()

# Reopen stdout as unbuffered. This will mean log messages will appear as soon as they become avaliable.
sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', 0)

# Sync the database
try:
    check_call(["/usr/bin/keystone-manage","db_sync"],stdout = sys.stdout, stderr = sys.stderr, shell = False)
except CalledProcessError:
     print "The dbsync process failed to execute, terminating..."
     sys.exit(0) # Exiting with 0 exit code to prevent container from restarting

# Spawn the child
child_path = ["/usr/bin/keystone-all",]
child = Popen(child_path, stdout = PIPE, stderr = STDOUT, shell = False) 

# Output any log items to Docker
for line in iter(child.stdout.readline, ''):
    sys.stdout.write(line)

# If the process terminates, read its errorcode and return it
sys.exit(child.returncode)
