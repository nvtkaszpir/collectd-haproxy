# collectd-haproxy

This is a collectd plugin to pull HAProxy (<http://haproxy.1wt.eu>) stats from the HAProxy management socket.
It is written in Python and as such, runs under the collectd Python plugin.

# Requirements


*HAProxy*
To use this plugin, HAProxy must be configured to create a management socket with the `stats socket`
configuration option. collectd must have read/write access to the socket.

*collectd*
collectd must have the Python plugin installed. See (<http://collectd.org/documentation/manpages/collectd-python.5.shtml>)

# Options
* `ProxyMonitor`
Proxy to monitor. If unset, defaults to ['server', 'frontend', 'backend'].
Specify multiple times to specify additional proxies
* `ProxyIgnore`
One or more Proxies to ignore
 Specify multiple times to specify additional proxies
* `Socket`
File location of the HAProxy management socket
* `Verbose`
Enable verbose logging
* `Url`
Set URL to fetch HAproxy stats page from remote server, see examples.
Do not add `;csv` at the end.
* `Timeout`
Timeout in seconds for connecting to HAproxy via URL
* `Realm`
String in double quotes which represents HTTP Basic Auth Realm, defaults to "HAProxy Statistics"
* `Username`
String in double quotes which represents HTTP Basic Auth User Name.
* `Password`
String in double quotes which represents HTTP Basic Auth User Password.

Both Username and Password must be set if authorization is required

# Known limitaions
* Does not work with multiple instances yet (last value will overwrite other), so right now this script can monitor only one instance of the haproxy
* Python error and collectd plugin getting suspended when failed to fetch stats via HTTP
* HTTPS was not tested.
* Does not fetch HAproxy info via HTTP.

# Examples

## Via UNIX socket

Connenct via UNIX socket:

```text
<LoadPlugin python>
  Globals true
</LoadPlugin>

<Plugin python>
  # haproxy.py is at /usr/lib64/collectd/haproxy.py
  ModulePath "/usr/lib64/collectd/"

  Import "haproxy"

  <Module haproxy>
    Socket "/var/run/haproxy.sock"
    ProxyMonitor "server"
    ProxyMonitor "backend"
  </Module>
</Plugin>
```

## Via HTTP stats page on to remote instance

Get stats from remove server by fetching HTTP stats page with authorization
Please refer to [official HAProxy documentation](https://cbonte.github.io/haproxy-dconv/1.7/configuration.html#stats admin).

First, you must set proper authorization in HAproxy, for example:

```text
listen stats
    bind 0.0.0.0:1234
    mode  http
    stats enable
    stats realm Haproxy\ Statistics
    stats uri /haproxy
    stats auth stats_user:stats_admin
    stats admin if TRUE

```

```text
<LoadPlugin python>
  Globals true
</LoadPlugin>

<Plugin python>
  ModulePath "/usr/share/collectd/collectd-haproxy"
  Import "haproxy"

  <Module haproxy>
    Url "http://127.0.0.1:1234/haproxy"
    Verbose True
    Timeout 2
    Realm "Haproxy Statistics"
    Username "stats_user"
    Password "stats_admin"
  </Module>

```
