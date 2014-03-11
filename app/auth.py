#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os, ldap, uuid, time, jwt, logging, re, traceback
from flask import Flask, session, flash, redirect, url_for, escape, abort, request, g
from flask import render_template
from flaskext.yamlconfig import AppYAMLConfig, install_yaml_config
from pprint import pprint as pprint

app = Flask(__name__)

# Setup app configuration from yaml file
install_yaml_config(app)
AppYAMLConfig(app,os.path.join(os.path.dirname(os.path.abspath(__file__)),'config.yaml'))

# Configure logging
loglevel = app.config['LOG_LEVEL'] if 'LOG_LEVEL' in app.config else logging.WARNING
logformat = logging.Formatter(app.config['LOG_FORMAT'] if 'LOG_FORMAT' in app.config else '%(asctime)s - [%(pathname)s:%(lineno)d] %(name)s - %(levelname)s - %(message)s')
console_handler = logging.StreamHandler()
console_handler.setLevel(loglevel)
console_handler.setFormatter(logformat)

logfile_handler = logging.FileHandler(app.config['LOG_FILE'] if 'LOG_FILE' in app.config else '/dev/null')
logfile_handler.setLevel(loglevel)
logfile_handler.setFormatter(logformat)

app.logger.setLevel(loglevel)
app.logger.addHandler(console_handler)
app.logger.addHandler(logfile_handler)

app.secret_key = os.urandom(24)

ldap_connections = {}


def ldap_conn(server,bind_dn,password,timeout,retry_max,retry_delay):
    conn = ldap.ldapobject.ReconnectLDAPObject(server,retry_max=retry_max,retry_delay=retry_delay)
    conn.timeout = timeout 

    try:
        app.logger.debug("Trying to bind as %s" % (bind_dn,))
        conn.simple_bind_s(bind_dn,password)
        app.logger.debug("Successfully bound to %s" % (server,))
        return conn
    except (ldap.INVALID_CREDENTIALS, ldap.UNWILLING_TO_PERFORM, ldap.INVALID_DN_SYNTAX), e:
        app.logger.warning("Invalid Credentials trying to bind to %s as %s (%s)" % (server,bind_dn,e))
        return False
    except Exception, e:
        app.logger.error("Unknown error attempting to bind to %s as %s (%s)" % (server,bind_dn,e))
        flash('Unknown error occurred attempting to query auth server')
        return False
    return False


def return_persistent_connection(ldap_server,force=False):
    if ldap_server in ldap_connections and not force:
        app.logger.debug("Returning already-open ldap connection %s" % (ldap_server,))
        return ldap_connections[ldap_server]
    else:
        app.logger.debug("Returning new ldap connection %s" % (ldap_server,))
        ldap_config = app.config['LDAP_SERVERS'][ldap_server]
        ldap_connection = ldap_conn(ldap_server,ldap_config['bind_dn'],ldap_config['password'],ldap_config['timeout'],ldap_config['retry_max'],ldap_config['retry_delay'])
        ldap_connections[ldap_server] = ldap_connection
        return ldap_connection


def ldap_authenticate(username,password):
    # Attempt to authenticate against a list of LDAP servers
    for ldap_server,ldap_config in app.config['LDAP_SERVERS'].items():
        app.logger.debug("Attempting to authenticate user %s with server %s" %(username,ldap_server))
        master_conn = return_persistent_connection(ldap_server)

        if not master_conn or not master_conn._l:
            app.logger.error("Master connection for ldap server %s is invalid, trying to reconnect..." % (ldap_server,))
        
            master_conn = return_persistent_connection(ldap_server,True)

            if not master_conn or not master_conn._l:
                app.logger.error("Master connection for ldap server %s is STILL invalid. Aborting..." % (ldap_server,))
                return False

        ldap_attrs = ldap_config.get('attrs',{})
        ldap_sso_map = ldap_config.get('sso_map',{})
        ldap_sso_static = ldap_config.get('static_attributes',{})
        if 'user_sanitize' in ldap_config:
            sanitize_regex = ldap_config.get('user_sanitize',{}).get('regex','')
            sanitize_replace = ldap_config.get('user_sanitize',{}).get('replace','')
            username = re.sub(sanitize_regex,sanitize_replace,username)
            app.logger.debug("Sanitized username is '%s'" % (username,))

        ldap_filter = ldap_config.get('filter','').format(username=username)
        ldap_base_dn = ldap_config.get('base_dn','')

        # Find user in queryable DNs
    
        user_details = master_conn.search_ext_s(ldap_base_dn,ldap.SCOPE_SUBTREE,ldap_filter,attrlist=ldap_attrs)

        # Check if a user was found
        if len(user_details) < 1: 
            app.logger.warning("No User Found for username %s" % (username,))
            continue

        # Attempt to bind as the user
        user_dn = user_details[0][0]
        app.logger.debug("Server: %s DN: %s Timeout: %s" %(ldap_server,user_dn,ldap_config['timeout']))

        userconn = ldap_conn(ldap_server,user_dn,password.encode('utf-8'),ldap_config['timeout'],ldap_config['retry_max'],ldap_config['retry_delay'])

        if userconn:
            app.logger.debug("Successfully bound as %s (%s)" % (user_dn,user_details[0][1]))
            # Normalize user data based on SSO type
            return normalize_sso(user_details[0][1],ldap_sso_map,ldap_sso_static)
        else:
            app.logger.debug("Unable to bind to %s as %s" % (ldap_server,user_dn))

    return False


def login():
    # Allow cookie-based login assuming the session is authenticated and expires later than now
    if session.get('authenticated',False) and session.get('expires',0) > time.time():
        app.logger.debug("User authenticated by existing cookie: %s" % (session.get('userdata',{}),))
        return redirect_sso()
    
    if request.method == 'POST':
        try:
            user = ldap_authenticate(request.form['username'],request.form['password'])
            if user is not False:
                app.logger.debug("USER: %s" % (user,))
                session['authenticated'] = True
                session['userdata'] = user 
                session['expires'] = time.time() + (86400 * 7)
                app.logger.debug("User logged in successfully: %s" % (session,))
                return redirect_sso()
            else:
                app.logger.debug("User did not login successfully: %s" % (session,))
                flash('Username or password incorrect - please try again.')
                return redirect(request.url)
        except Exception, e:
            app.logger.error("Uncaught error attempting to auth with LDAP: %s" % (e,))
            app.logger.error("Traceback: %s" % (traceback.format_exc(),))
            flash('Unable to auth - unknown error occurred. Please contact support@squiz.co.uk')
            return redirect(request.url)

        
    else:

        # Check if this has passed through and has an SSO type stored, if not, error
        if not session.get('sso_type',False):
            app.logger.warning("Login session misplaced (no sso_type stored): %s" % (session,))
            flash('Your login session has been misplaced - please try to authenticate again.')    

        return render_template('login.html')


def normalize_sso(userdata,sso_types,static_attributes):
    sso_type = session.get('sso_type','').lower()

    if sso_type.lower() not in sso_types:
        app.logger.error("SSO Type %s does not have an attribute map (sso_map) for one of your ldap servers." % (sso_type,))
        return {}

    mapdata = {}
    # Map user details to relevant SSO fields
    for ldap_attr,sso_attr in sso_types.get(sso_type,{}).items():
        if ldap_attr not in userdata:
            app.logger.error("Tried to set an SSO attribute %s mapping to %s" % (ldap_attr,sso_attr))
            continue
        mapdata[sso_attr] = userdata[ldap_attr][0]

    # Add static attributes for this SSO type
    #for attr,value in static_attributes.get(sso_type,{}).items():
    #    mapdata[attr] = value

    return mapdata


def redirect_sso():
    sso_type = session.get('sso_type',False)

    if not sso_type:
        app.logger.error("SSO Type could not be retrieved from session: %s" % (session,))
        abort(404)

    app.logger.debug("Redirecting user for SSO Type %s" % (sso_type,))
    return redirect(url_for('return_%s' % (sso_type.lower(),)))


@app.route("/jwt/<provider>/login",methods=['GET','POST'])
def login_jwt(provider):
    if provider not in app.config['JWT_PROVIDERS']:
        app.logger.warning("Provider %s not found at %s" % (provider,request.url))
        return abort(404)

    session['sso_type'] = 'jwt'
    session['sso_provider'] = provider
    return login()


@app.route("/jwt/<provider>/logout",methods=['GET'])
def logout_jwt(provider):
    if provider not in app.config['JWT_PROVIDERS']:
        app.logger.warning("Provider %s not found at %s" % (provider,request.url))
        return abort(404)

    session['sso_type'] = 'jwt'
    session['sso_provider'] = provider
    session['authenticated'] = False

    logout_message = request.args.get('message') or 'You have been logged out'
    flash(logout_message)

    return redirect(url_for('login_jwt',provider=provider))


@app.route("/return_jwt",methods=['GET'])
def return_jwt():
    sso_provider = session.get('sso_provider',False)
    if sso_provider not in app.config['JWT_PROVIDERS']:
        app.logger.error("SSO Provider %s not in valid JWT provider list" % (sso_provider,))
        abort(500)

    provider_config = app.config['JWT_PROVIDERS'][sso_provider]

    payload = {
        "iat": int(time.time()),
        "jti": str(uuid.uuid4()),
    }

    payload.update(session.get('userdata',{}))

    # Generate JWT URL
    jwt_string = jwt.encode(payload, provider_config['shared_key'])
    sso_url = provider_config['callback'].format(jwt_payload=jwt_string)

    app.logger.debug("JWT Data: %s" % (payload,))
    app.logger.debug("JWT Url: %s" % (sso_url,)) 
    return redirect(sso_url)


@app.errorhandler(404)
def page_not_found(error):
    return 'This page does not exist', 404

if __name__ == "__main__":
    app.run(host='0.0.0.0',port=3000,debug=True)

# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
