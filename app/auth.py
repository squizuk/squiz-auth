import os, ldap, uuid, time, jwt, logging
from flask import Flask, session, flash, redirect, url_for, escape, abort, request, g
from flask import render_template
from flaskext.yamlconfig import AppYAMLConfig
from flaskext.yamlconfig import install_yaml_config

app = Flask(__name__)

# Setup app configuration from yaml file
install_yaml_config(app)
AppYAMLConfig(app,os.path.join(os.path.dirname(os.path.abspath(__file__)),'config.yaml'))

# Configure logging
loglevel = app.config['LOG_LEVEL'] if 'LOG_LEVEL' in app.config else logging.WARNING
logformat = logging.Formatter(app.config['LOGFORMAT'] if 'LOGFORMAT' in app.config else '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
console_handler = logging.StreamHandler()
console_handler.setLevel(loglevel)
console_handler.setFormatter(logformat)

app.logger.setLevel(loglevel)
app.logger.addHandler(console_handler)

app.logger.info('LogLevel set to %d' % (loglevel,))

app.secret_key = os.urandom(24)

ldap_connections = {}

def ldap_conn(server,bind_dn,password,timeout):
    conn = ldap.initialize(server)
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

def return_persistent_connection(ldap_server):
    if ldap_server in ldap_connections:
        app.logger.debug("Returning already-open ldap connection %s" % (ldap_server,))
        return ldap_connections[ldap_server]
    else:
        app.logger.debug("Returning new ldap connection %s" % (ldap_server,))
        ldap_config = app.config['LDAP_SERVERS'][ldap_server]
        ldap_connection = ldap_conn(ldap_server,ldap_config['bind_dn'],ldap_config['password'],ldap_config['timeout'])
        ldap_connections[ldap_server] = ldap_connection
        return ldap_connection


def ldap_authenticate(username,password):
    # Attempt to authenticate against a list of LDAP servers
    for ldap_server,ldap_config in app.config['LDAP_SERVERS'].items():
        app.logger.debug("Attempting to authenticate user %s with server %s" %(username,ldap_server))
        master_conn = return_persistent_connection(ldap_server)

        if not master_conn:
            app.logger.error("Master connection for ldap server %s is invalid" % (ldap_server,))
            return False
        
        ldap_attrs = ldap_config['attrs']
        ldap_filter = ldap_config['filter'].format(uid=username)
        ldap_base_dn = ldap_config['base_dn']

        # Find user in queryable DNs
    
        user_details = master_conn.search_s(ldap_base_dn,ldap.SCOPE_SUBTREE,ldap_filter,attrlist=ldap_attrs)

        # Check if a user was found
        if len(user_details) < 1: 
            app.logger.warning("No User Found for username %s" % (username,))
            return False

        # Attempt to bind as the user
        user_dn = user_details[0][0]
        app.logger.debug("Server: %s DN: %s Timeout: %s" %(ldap_server,user_dn,ldap_config['timeout']))

        userconn = ldap_conn(ldap_server,user_dn,password,ldap_config['timeout'])

        if userconn:
            app.logger.debug("Successfully bound as %s (%s)" % (user_dn,user_details[0][1]))
            return user_details[0][1]
        else:
            app.logger.debug("Unable to bind to %s as %s" % (ldap_server,user_dn))

    return False


@app.route("/")
def index():
    return redirect(url_for('login'))


@app.route("/jwt/<provider>/login",methods=['GET'])
def login_jwt(provider):
    if provider not in app.config['JWT_PROVIDERS']:
        app.logger.warning("Provider %s not found at %s" % (provider,request.url))
        return abort(404)

    session['sso_type'] = 'JWT'
    session['sso_provider'] = provider

    return redirect(url_for('login'))


@app.route("/jwt/<provider>/logout",methods=['GET'])
def logout_jwt(provider):
    if provider not in app.config['JWT_PROVIDERS']:
        app.logger.warning("Provider %s not found at %s" % (provider,request.url))
        return abort(404)

    session['sso_type'] = 'JWT'
    session['sso_provider'] = provider
    session['authenticated'] = False

    flash('You have been logged out.')

    return redirect(url_for('login'))


@app.route("/login",methods=['GET', 'POST'])
def login():
    # Allow cookie-based login assuming the session is authenticated and expires later than now
    if session.get('authenticated',False) and session.get('expires',0) > time.time():
        app.logger.debug("User authenticated by existing cookie: %s" % (session.get('userdata',{}),))
        return redirect_sso()
    
    if request.method == 'POST':
        return do_login()
    else:

        # Check if this has passed through and has an SSO type stored, if not, error
        if not session.get('sso_type',False):
            app.logger.warning("Login session misplaced (no sso_type stored): %s" % (session,))
            flash('Your login session has been misplaced - please try to authenticate again.')    

        return render_template('login.html')


def do_login():
    user = ldap_authenticate(request.form['username'],request.form['password'])
    if user is not False:
        session['authenticated'] = True
        session['userdata'] = user 
        session['expires'] = time.time() + (3600 * 24)
        app.logger.debug("User logged in successfully: %s" % (session,))
        return redirect_sso()
    else:
        app.logger.debug("User did not login successfully: %s" % (session,))
        flash('Username or password incorrect - please try again.')
        return redirect(url_for('login'))


def redirect_sso():

    sso_types = {
        'JWT': 'return_jwt',
        False: 'return_jwt',
    }

    sso_type = session.get('sso_type',False)
    return_sso_method = sso_types[sso_type]

    app.logger.debug("Redirecting user for SSO Type %s, resolving to method %s" % (sso_type,return_sso_method))
    return redirect(url_for(return_sso_method))


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

    # Populate JWT payload
    for ldap_attr,jwt_attr in provider_config['ldap_map'].items():
        if ldap_attr not in session['userdata']:
            app.logger.error("Tried to set a JWT attribute %s that doesnt exist for this user: %s" % (jwt_attr,ldap_attr))
            continue
        payload[jwt_attr] = session['userdata'][ldap_attr][0] 

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
    app.run(host='0.0.0.0',port=3000)

# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
