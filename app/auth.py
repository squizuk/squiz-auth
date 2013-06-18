from flask import Flask, session, flash, redirect, url_for, escape, abort, request, g
from flask import render_template
from flaskext.yamlconfig import AppYAMLConfig
from flaskext.yamlconfig import install_yaml_config
import os, ldap, uuid, time, jwt, logging

app = Flask(__name__)
install_yaml_config(app)
AppYAMLConfig(app,os.path.join(os.path.dirname(os.path.abspath(__file__)),'config.yaml'))
#app.debug = True
app.secret_key = os.urandom(24)

ldap_connections = {}

def ldap_conn(server,bind_dn,password,timeout):
    conn = ldap.initialize(server)
    conn.timeout = timeout 

    try:
        print "Trying to bind as %s" % (bind_dn)
        conn.simple_bind_s(bind_dn,password)
        print "Successfully bound to %s" % (server)
        return conn
    except (ldap.INVALID_CREDENTIALS, ldap.UNWILLING_TO_PERFORM, ldap.INVALID_DN_SYNTAX), e:
        print "Invalid Credentials %s" % (e)
        return False
    except Exception, e:
        print "Unknown %s" % (e)
        flash('Unknown error occurred attempting to query auth server')
        return False
    return False

def return_persistent_connection(ldap_server):
    if ldap_server in ldap_connections:
        return ldap_connections[ldap_server]
    else:
        print "Returning new ldap connection %s" % (ldap_server)
        ldap_config = app.config['LDAP_SERVERS'][ldap_server]
        ldap_connection = ldap_conn(ldap_server,ldap_config['bind_dn'],ldap_config['password'],ldap_config['timeout'])
        ldap_connections[ldap_server] = ldap_connection
        return ldap_connection


def ldap_authenticate(username,password):
    # Attempt to authenticate against a list of LDAP servers
    for ldap_server,ldap_config in app.config['LDAP_SERVERS'].items():

        master_conn = return_persistent_connection(ldap_server)

        if not master_conn:
            return False
        
        ldap_attrs = ldap_config['attrs']
        ldap_filter = ldap_config['filter'].format(uid=username)
        ldap_base_dn = ldap_config['base_dn']

        # Find user in queryable DNs
    
        user_details = master_conn.search_s(ldap_base_dn,ldap.SCOPE_SUBTREE,ldap_filter,attrlist=ldap_attrs)

        # Check if a user was found
        if len(user_details) < 1: 
            print "No User Found"
            return False

        # Attempt to bind as the user
        user_dn = user_details[0][0]
        print "Server: %s DN: %s Timeout: %s" %(ldap_server,user_dn,ldap_config['timeout'])

        userconn = ldap_conn(ldap_server,user_dn,password,ldap_config['timeout'])

        if userconn:
            return user_details[0][1]
        else:
            print "Unable to auth to %s" % (ldap_server)

    return False


@app.route("/")
def index():
    return redirect(url_for('login'))


@app.route("/jwt/<provider>/login",methods=['GET'])
def login_jwt(provider):
    if provider not in app.config['JWT_PROVIDERS']:
        return abort(404)

    session['sso_type'] = 'JWT'
    session['sso_provider'] = provider

    return redirect(url_for('login'))


@app.route("/jwt/<provider>/logout",methods=['GET'])
def logout_jwt(provider):
    if provider not in app.config['JWT_PROVIDERS']:
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
        return redirect_sso()
    
    if request.method == 'POST':
        return do_login()
    else:

        # Check if this has passed through and has an SSO type stored, if not, error
        if not session.get('sso_type',False):
            flash('Your login session has been misplaced - please try to authenticate again.')    

        return render_template('login.html')


def do_login():
    user = ldap_authenticate(request.form['username'],request.form['password'])
    if user is not False:
        session['authenticated'] = True
        session['userdata'] = user 
        session['expires'] = time.time() + (3600 * 24)
        return redirect_sso()
    else:
        flash('Username or password incorrect - please try again.')
        return redirect(url_for('login'))


def redirect_sso():

    sso_types = {
        'JWT': 'return_jwt',
        False: 'return_jwt',
    }

    return redirect(url_for(sso_types[session.get('sso_type',False)]))


@app.route("/return_jwt",methods=['GET'])
def return_jwt():
    sso_provider = session.get('sso_provider',False)
    if sso_provider not in app.config['JWT_PROVIDERS']:
        abort(500)

    provider_config = app.config['JWT_PROVIDERS'][sso_provider]

    payload = {
        "iat": int(time.time()),
        "jti": str(uuid.uuid4()),
    }

    # Populate JWT payload
    for ldap_attr,jwt_attr in provider_config['ldap_map'].items():
        payload[jwt_attr] = session['userdata'][ldap_attr][0] 

    # Generate JWT URL
    jwt_string = jwt.encode(payload, provider_config['shared_key'])
    sso_url = provider_config['callback'].format(jwt_payload=jwt_string)

    return redirect(sso_url)

@app.errorhandler(404)
def page_not_found(error):
    return 'This page does not exist', 404

if __name__ == "__main__":
    app.run(host='0.0.0.0',port=3000)

# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
