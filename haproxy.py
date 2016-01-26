# haproxy-collectd-plugin - haproxy.py
#
# Author: Michael Leinartas
# Description: This is a collectd plugin which runs under the Python plugin to
# collect metrics from haproxy.
# Plugin structure and logging func taken from
# https://github.com/phrawzty/rabbitmq-collectd-plugin
#
# Modified by "Warren Turkal" <wt@signalfuse.com>

# Known limitations:
# - does not work witl multiple instances, the last on eoverwrite all other settings
# - plugin python when failed to fetch remote stats
# - not tested via https

import cStringIO as StringIO
import socket
import csv
import urllib2
import base64

import collectd

PLUGIN_NAME = 'haproxy'
RECV_SIZE = 1024
METRIC_TYPES = {
    'MaxConn': ('max_connections', 'gauge'),
    'CumConns': ('connections', 'counter'),
    'CumReq': ('requests', 'counter'),
    'MaxConnRate': ('max_connection_rate', 'gauge'),
    'MaxSessRate': ('max_session_rate', 'gauge'),
    'MaxSslConns': ('max_ssl_connections', 'gauge'),
    'CumSslConns': ('ssl_connections', 'counter'),
    'MaxSslConns': ('max_ssl_connections', 'gauge'),
    'MaxPipes': ('max_pipes', 'gauge'),
    'Idle_pct': ('idle_pct', 'gauge'),
    'Tasks': ('tasks', 'gauge'),
    'Run_queue': ('run_queue', 'gauge'),
    'PipesUsed': ('pipes_used', 'gauge'),
    'PipesFree': ('pipes_free', 'gauge'),
    'Uptime_sec': ('uptime_seconds', 'counter'),
    'bin': ('bytes_in', 'counter'),
    'bout': ('bytes_out', 'counter'),
    'chkfail': ('failed_checks', 'counter'),
    'downtime': ('downtime', 'counter'),
    'dresp': ('denied_response', 'counter'),
    'dreq': ('denied_request', 'counter'),
    'econ': ('error_connection', 'counter'),
    'ereq': ('error_request', 'counter'),
    'eresp': ('error_response', 'counter'),
    'hrsp_1xx': ('response_1xx', 'counter'),
    'hrsp_2xx': ('response_2xx', 'counter'),
    'hrsp_3xx': ('response_3xx', 'counter'),
    'hrsp_4xx': ('response_4xx', 'counter'),
    'hrsp_5xx': ('response_5xx', 'counter'),
    'hrsp_other': ('response_other', 'counter'),
    'qcur': ('queue_current', 'gauge'),
    'rate': ('session_rate', 'gauge'),
    'req_rate': ('request_rate', 'gauge'),
    'stot': ('session_total', 'counter'),
    'act': ('active_servers', 'gauge'),
    'bck': ('backup_servers', 'gauge'),
    'scur': ('session_current', 'gauge'),
    'wredis': ('redistributed', 'counter'),
    'wretr': ('retries', 'counter'),
    'slim': ('session_limit', 'gauge'),
    'wredis': ('redistributed', 'derive'),
    'wretr': ('retries', 'derive'),
}
}

METRIC_DELIM = '.'  # for the frontend/backend stats

DEFAULT_SOCKET = '/var/lib/haproxy/stats'
DEFAULT_BASE_URL = 'http://localhost/;csv'
VERBOSE_LOGGING = False
HAPROXY_SOCKET = None
HAPROXY_URL = None
HAPROXY_INSTANCE = None
USERNAME = None
PASSWORD = None
REALM = "HAProxy Statistics"
TIMEOUT = 2 # seconds

class Logger(object):
    def error(self, msg):
        collectd.error('{name}: {msg}'.format(name=PLUGIN_NAME, msg=msg))

    def notice(self, msg):
        collectd.warning('{name}: {msg}'.format(name=PLUGIN_NAME, msg=msg))

    def warning(self, msg):
        collectd.notice('{name}: {msg}'.format(name=PLUGIN_NAME, msg=msg))

    def verbose(self, msg):
        if VERBOSE_LOGGING:
            collectd.info('{name}: {msg}'.format(name=PLUGIN_NAME, msg=msg))

log = Logger()


class HAProxySocket(object):
    def __init__(self, socket_file=DEFAULT_SOCKET):
        self.socket_file = socket_file

    def connect(self):
        stat_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        stat_sock.connect(self.socket_file)
        return stat_sock

    def communicate(self, command):
        '''Get response from single command.

        Args:
            command: string command to send to haproxy stat socket

        Returns:
            a string of the response data
        '''
        if not command.endswith('\n'):
            command += '\n'
        stat_sock = self.connect()
        stat_sock.sendall(command)
        result_buf = StringIO.StringIO()
        buf = stat_sock.recv(RECV_SIZE)
        while buf:
            result_buf.write(buf)
            buf = stat_sock.recv(RECV_SIZE)
        stat_sock.close()
        return result_buf.getvalue()

    def get_server_info_data(self):
        return self.communicate('show info')

    def get_server_info(self):
        result = {}
        output = self.get_server_info_data()
        for line in output.splitlines():
            try:
                key, val = line.split(':', 1)
            except ValueError:
                continue
            result[key.strip()] = val.strip()
        return result

    def get_server_stats_data(self):
        return self.communicate('show stats')

    def get_server_stats(self):
        output = self.get_server_stats_data()
        #sanitize and make a list of lines
        output = output.lstrip('# ').strip()
        output = [l.strip(',') for l in output.splitlines()]
        csvreader = csv.DictReader(output)
        result = [d.copy() for d in csvreader]
        return result

    def get_stats(self):
        stats = {}

        try:
            server_info = self.get_server_info()
            server_stats = self.get_server_stats()
        except socket.error:
            log.warning(
                'status err Unable to connect to HAProxy socket at %s' %
                HAPROXY_SOCKET)
            return stats

        for key, val in server_info.iteritems():
            try:
                stats[key] = int(val)
            except (TypeError, ValueError):
                pass

        ignored_svnames = set(['BACKEND'])
        for statdict in server_stats:
            if statdict['svname'] in ignored_svnames:
                continue
            for key, val in statdict.items():
                metricname = METRIC_DELIM.join(
                    [statdict['svname'].lower(), statdict['pxname'].lower(), key])
                try:
                    stats[metricname] = int(val)
                except (TypeError, ValueError):
                    pass
        return stats


class HAProxyHttp(HAProxySocket):
    def __init__(self, base_url):
        self.base_url = base_url

    def _get_data(self):
        '''Get response from the stats api.

        Returns:
            a string of the response data
        '''

        url = self.base_url + '/;csv'
        try_url = url + ", u:{}, p:{}".format(USERNAME, PASSWORD)
        log.verbose('Trying url: {}'.format(try_url))
        try:
            if USERNAME and PASSWORD:
                auth_handler = urllib2.HTTPBasicAuthHandler()
                auth_handler.add_password(
                    realm=REALM,
                    uri=url,
                    user=USERNAME,
                    passwd=PASSWORD)
                opener = urllib2.build_opener(auth_handler)
                urllib2.install_opener(opener)
            request = urllib2.urlopen(url, timeout=TIMEOUT)
            response = request.read()
            return response
        except urllib2.URLError, e:
            collectd.error('haproxy plugin: Error connecting to %s - %s' % (try_url, e))
            return None

    def get_server_info_data(self):
        # still figuring out if I can get server info via http
        return ""

    def get_server_stats_data(self):
        return self._get_data()


def get_stats():
    # check for HAPROXY_URL first for backwards compat with HAPROXY_SOCKET
    if HAPROXY_URL is not None:
        return HAProxyHttp(HAPROXY_URL).get_stats()
    elif HAPROXY_SOCKET is not None:
        return HAProxySocket(HAPROXY_SOCKET).get_stats()
    else:
        return None


def configure_callback(conf):
    global HAPROXY_SOCKET, HAPROXY_URL, HAPROXY_INSTANCE, VERBOSE_LOGGING, USERNAME, PASSWORD
    HAPROXY_SOCKET = DEFAULT_SOCKET
    VERBOSE_LOGGING = False

    for node in conf.children:
        if node.key == "Socket":
            HAPROXY_SOCKET = node.values[0]
        elif node.key == "Url":
            HAPROXY_URL = node.values[0]
        elif node.key == "Username":
            USERNAME = node.values[0]
        elif node.key == "Realm":
            REALM = node.values[0]
        elif node.key == "Password":
            PASSWORD = node.values[0]
        elif node.key == "Instance":
            HAPROXY_INSTANCE = node.values[0]
        elif node.key == "Verbose":
            VERBOSE_LOGGING = bool(node.values[0])
        elif node.key == "Timeout":
            TIMEOUT = int(node.values[0])
        else:
            log.warning('Unknown config key: %s' % node.key)


def read_callback():
    log.verbose('beginning read_callback')
    info = get_stats()

    if not info:
        log.warning('%s: No data received' % PLUGIN_NAME)
        return

    for key, value in info.iteritems():
        key_prefix = ''
        key_root = key
        if value not in METRIC_TYPES:
            try:
                key_prefix, key_root = key.rsplit(METRIC_DELIM, 1)
            except ValueError:
                pass

        if key_root not in METRIC_TYPES:
            continue

        key_root, val_type = METRIC_TYPES[key_root]
        if key_prefix == '':
            key_name = key_root
        else:
            key_name = METRIC_DELIM.join([key_prefix, key_root])
        log.verbose('{0}: {1}'.format(key_name, value))
        val = collectd.Values(plugin=PLUGIN_NAME, type=val_type)
        val.type_instance = key_name
        val.values = [value]
        val.meta = {'bug_workaround': True}

        # only set plugin_instance if it is set for backwards compat
        if HAPROXY_INSTANCE:
            val.plugin_instance = HAPROXY_INSTANCE

        val.dispatch()


collectd.register_config(configure_callback)
collectd.register_read(read_callback)
