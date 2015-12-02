import os
from ConfigParser import SafeConfigParser

import ldap
import ldap.filter
from flask import Flask, render_template, request

CONFIG_FILE = os.path.join(os.path.dirname(__file__), 'config.ini')

passwd = Flask(__name__)

def get_config(config_file=CONFIG_FILE):
    parser = SafeConfigParser()
    parser.read(config_file)

    return parser

def get_evt_ldap_conn(host, cert_file):
    ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_DEMAND)
    ldap.set_option(ldap.OPT_X_TLS_CACERTFILE, cert_file)

    return ldap.initialize('ldaps://%s:636' % host)

@passwd.route('/')
def form():
    return render_template('form.html')

@passwd.route('/chgpass', methods=['POST'])
def chgpass():
    user = request.form.get('username', '')
    passwd = request.form.get('password', '')

    passwd1 = request.form.get('password1', '')
    passwd2 = request.form.get('password2', '')

    config = get_config()
    ldap_host = config.get('ldap', 'host')
    cert_file = config.get('ldap', 'cert_file')
    users_dn = config.get('ldap', 'user_dn')
    user_filter= config.get('ldap', 'user_filter')
    min_length = config.getint('password', 'min_length')

    ldaph = get_evt_ldap_conn(ldap_host, cert_file)

    if passwd1 != passwd2:
        return render_template('form.html', username=user, error='Passwords do not match!')

    elif len(passwd1) < min_length:
        return render_template('form.html', username=user,
                               error='Password must be at least %s characters.' % min_length)

    user_search_filter = ldap.filter.filter_format(user_filter, (user,))
    dn, _ = get_user_by_filter(ldaph, users_dn, user_search_filter, [])
    authenticated = False

    if dn:
        try:
            ldaph.bind_s(dn, passwd)
            authenticated = True
        except ldap.INVALID_CREDENTIALS:
            pass

        except ldap.LDAPError:
            return render_template('form.html', error='An error occured.', username=user)

    if not authenticated:
        return render_template('form.html', error='Invalid username or password!',
                               username=user)
    try:
        ldaph.passwd_s(dn, passwd, passwd1)

    # passwords don't match. It refuses.
    except ldap.UNWILLING_TO_PERFORM:
        return render_template('form.html', error='Invalid username or password!')

    except ldap.LDAPError:
        return render_template('form.html', error='Password change failed!',
                               username=user)

    return render_template('form.html', w00t='Password changed!')


def get_user_by_filter(conn, users_dn, filter, attrs=None):
    result_data = conn.search_s(users_dn, ldap.SCOPE_SUBTREE, filter, attrs)

    if len(result_data) == 1:
        return result_data[0] # dn, {data}
    else:
        return None, None

if __name__ == '__main__':
    passwd.run()
