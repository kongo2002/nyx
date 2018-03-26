
# nyx

*nyx* is a lean process monitoring tool written in *C*.

[![build status](https://api.travis-ci.org/kongo2002/nyx.svg)][travis]

You can easily configure numerous processes that should be monitored and watched
to be in a running and healthy state and restarted if necessary. You should be
up and running with almost zero configuration at all as *nyx* tries to ship with
sane default configuration values.


### Features

- applications are being watched and kept alive (i.e. restarted) automatically
- simple [YAML][yaml] configuration
- observe processes' CPU/memory utilization
- check for opened ports if configured
- validate configurable HTTP endpoints
- [docker][docker] compatible `init` replacement
- control applications via command interface (unix domain socket)
- minimal dependencies
- small memory footprint
- C plugin architecture *(disabled by default)*

The project is inspired by [god][god] - the great ruby process monitor.


### Why?

You might think, 'why would you build another process manager when there are
numerous working ones already?'

Yes, you are right - there are several ones out there but none of it fits
exactly what I am looking for:

* [god][god]: this is the closest one. Sadly you need to have ruby installed on
  your machine and the configuration quickly gets complicated when you just want
  to say: 'this is my service - just keep it running!'

* [supervisor][supervisor]: also a nice one! This time you need to have a
  working python installation in place. Moreover it has become rather
  *huge* with *a lot* of functionality that has to be incorporated in a messy
  configuration format: like *INI*

* [systemd][systemd] (and other init systems): obviously too much! Often a full
  blown init system is just too much although some functionalities do overlap.

I wanted to have an application I can simply put on a machine that just works
without much dependency or configuration hassle to keep a couple of services up
and running. If really necessary I can get notified on status changes via some
plugin's functionality like XMPP.


### Event interface

On linux a *nyx* daemon running with root privileges may utilize the kernel
userspace connector to retrieve process events. That way there is *no need for
polling* the program's running status so that *nyx* recognizes a program
shutdown/failure immediately without any delay.

So you should consider checking the `CONFIG_CONNECTOR` kernel configuration for
this mechanism to work. Otherwise *nyx* will fallback to a polling approach (use
the `polling_interval` setting to modify the interval which defaults to 5
seconds).


## Get it!

Instead of [building](#building) nyx by yourself you can download ready-to-use
binaries for 64-bit Linux:


#### 1.9.0

- 64-bit static binary (built using musl libc): [nyx-1.9.0.tar.gz](http://uhlenheuer.net/files/nyx/static/nyx-1.9.0.tar.gz)
  (SHA1: `d9b0640c2f070ef2bae7d21547438c707ca81888`)


#### 1.8.0

- 64-bit static binary (built using musl libc): [nyx-1.8.0.tar.gz](http://uhlenheuer.net/files/nyx/static/nyx-1.8.0.tar.gz)
  (SHA1: `6edb94b02e0a86af69660e37223f1cfc3b3e6dd9`)


#### 1.7.1

- 64-bit static binary (built using musl libc): [nyx-1.7.1.tar.gz](http://uhlenheuer.net/files/nyx/static/nyx-1.7.1.tar.gz)
  (SHA1: `ca7ff793253775629089df3d7219e38598f9ac92`)


#### 1.6.1

- 64-bit Linux RPM: [nyx-1.6.1-1.x86_64.rpm](http://uhlenheuer.net/files/nyx/rpms/nyx-1.6.1-1.x86_64.rpm)
  (SHA1: `d3667aaf3ff17053b51e5bf6ea672a0eeb289bdc`)

- 64-bit static binary (built using musl libc): [nyx-1.6.1.tar.gz](http://uhlenheuer.net/files/nyx/static/nyx-1.6.1.tar.gz)
  (SHA1: `1c23bd10b3f5fe71476d527158f498cc0e294f7b`)


## Usage


### Docker

*nyx* is built especially with [docker][docker] usage in mind. This means *nyx*
is designed to be used as a [docker][docker] *ENTRYPOINT* that mimics the
behavior of the usual `init` process. That way you won't have issues with
*zombie processes* and such while keeping your applications monitored.

You could use something like the following in your base docker image:

```bash
ADD ./config.yaml /config.yaml

# it is important you use the 'exec' form of ENTRYPOINT
# for the process to be run directly (PID 1) without being
# invoked through /bin/sh -c
ENTRYPOINT ["nyx", "-c", "/config.yaml"]
```


### Daemon

The main *nyx* application is the so-called *daemon* that is started by
specifying the configuration file:

```bash
$ nyx -c config.yaml
```


#### Configuration

The daemon can be configured via a [YAML][yaml] file. An examplary configuration
file might look like this:

```yaml
# list of applications that will be watched by nyx
watches:
    # the name of the application
    app_name:

        # arbitrary executable
        start: /usr/bin/app -f /etc/app/some.config

        # user (optional)
        uid: user

        # group (optional)
        gid: user

        # working directory (optional)
        dir: /home/user

        # log (stdout) file (optional)
        log_file: /tmp/app.log

        # error (stderr) file (optional)
        error_file: /tmp/app.err

        # environment variables (optional)
        env:
            SOME: value
            FOO: bar

# general nyx settings
nyx:
    # log file location of the nyx daemon process
    # (optional)
    log_file: /var/log/nyx.log

    # interval between consecutive application checks (in sec)
    # this setting is used only in case the event interface
    # using the kernel userspace connector cannot be used
    # (optional)
    polling_interval: 5

    # size of the history of per-application states
    # (which can be observed via the 'history' command)
    # (optional)
    history_size: 20

    # you may configure nyx to open an additional port
    # that serves an HTTP endpoint similar to the local unix
    # domain socket
    # (optional)
    http_port: 8080

    # processes might require some startup time until ports
    # or http endpoints are spawned
    # the additional process checks will respect this delay (in sec)
    # (optional)
    startup_delay: 30
```


##### Program arguments

The program arguments of the `start` configuration value may be specified in a
YAML list style as well (which is especially useful with arguments containing
whitespace):

```yaml
watches:
    app:
        start: [
            '/usr/bin/app',
            '-f',
            '/etc/app/config.file'
        ]
```


##### Program termination

By default processes are stopped by sending a `SIGTERM` until after a timeout of
5 seconds a `SIGKILL` will finally terminate the process. However you may
configure a custom `stop` command that should handle the process' termination
and a `stop_timeout` in seconds until the `SIGKILL` will be fired:

```yaml
watches:
    app:
        start: /bin/app
        stop: /bin/app -terminate
        stop_timeout: 30
```


##### Watch process statistics

Additional to your processes being monitored by its running state you may
configure threshold values for CPU and/or memory usage. As soon as your process
exceeds the limit for a few consecutive snapshots the process is being
restarted.

```yaml
watches:
    app:
        start: /bin/app

        # maximum CPU usage of 98%
        max_cpu: 98

        # maximum memory usage of 2G
        max_memory: 2G
```

As of now a snapshot is taken every 30 seconds and the restart action is
executed a soon as at least 8 out of 10 snapshots exceed the configured
threshold.


##### Observe opened ports

Apart from watching the process itself you may instruct *nyx* to check if a
specified port is opened on the localhost. Use the setting `port_check` for that
purpose:

```yaml
watches:
    app:
        start: /usr/bin/mongod

        # i.e. watch the default mongodb port
        port_check: 27017
```

A process restart will be triggered if the port is not opened. This check will
be active after `startup_delay` seconds only (`30` by default) in order to
account for application initialization.


##### Check HTTP endpoint

Similarly to the `port_check` setting you may advise *nyx* to test for a
process' health using a configured HTTP endpoint. Use the `http_check`
setting(s) to configure the endpoint that is expected to return a `200 OK`
response:

```yaml
watches:
    app1:
        start: /usr/bin/app1

        http_check:
            url: /status
            port: 80
            method: GET

    # in case of a GET request on port 80 you may
    # use the shortened form of http_check as well:
    app2:
        start: /usr/bin/app2
        http_check: /status
```

This check respects the `startup_delay` configuration value as well (see
[above](#observe-opened-ports)).


#### Ad-hoc usage

You may specify an *ad-hoc* executable to *nyx* instead of passing a
configuration file with the `--run` command argument. This is a shortcut usage
that will initialize exactly one watch using the default configuration options:

```bash
$ nyx --run "mongod -f /etc/mongod.conf"
```

You must not use both ad-hoc executable *and* configuration file at the same
time.


#### Configuration directory

You may also specify a directory with the `-c` switch for nyx to read multiple
YAML files in the given folder. You must not rely on the order in which the
files should be read. Meaning in order to prevent surprises do not configure
duplicate config values or watches at all.

This feature may be especially useful in automated/provisioned environments like
[ansible][ansible] deployments for example.

```bash
# this way nyx will try to load all yaml files in '/etc/nyx.d'
$ nyx -c /etc/nyx.d
```


### Command interface

You can interact with a running *nyx* daemon instance using the same executable:

```bash
$ nyx version
<<< version
>>> 1.9.1
```

Right now the following commands are implemented:

- `ping`: ping a running daemon
- `version`: return the daemon version
- `status <watch>`: get the status of the specified watch
- `start <watch>`: send a start command to the specified watch
- `stop <watch>`: send a stop command to the specified watch
- `restart <watch>`: send a restart command to the specified watch
- `history <watch>`: get the latest events of the specified watch
- `config <watch>`: print the configuration of the specified watch
- `watches`: get all currently configured watches
- `reload`: reload the nyx configuration
- `terminate`: terminate the nyx daemon
- `quit`: stop the nyx daemon and all watched processes


### HTTP command interface

Similar to the default unix domain socket command interface you may configure
nyx with a `http_port`. That port serves an HTTP endpoint that responds to
*GET* requests like this:

```bash
$ curl localhost:8080/ping
>>> pong

$ curl localhost:8080/version
>>> 1.9.1

$ curl localhost:8080/stop/app
>>> requested stop for watch 'app'
```

The HTTP interface supports all commands of the usual command interface as well.


## Building

On most linux systems building should be as simple as cloning the git repository
and running `make`:

```bash
$ git clone git://github.com/kongo2002/nyx.git
$ cd nyx
$ make
$ ./nyx --help
```

System-wide installation can be achieved with a regular:

```bash
$ sudo make install
```

In order to run the test suite afterwards you may run:

```bash
$ make check
```


### Debug

The debug build can be compiled with:

```bash
$ make DEBUG=1
```


### Requirements

The following libraries are necessary to build and run *nyx*:

- `yaml`
- `cmocka` *(for unit tests only)*


### Plugin architecture

You may build a *plugin-enabled* nyx version by passing `PLUGINS=1`:

```bash
$ make PLUGINS=1
```

Moreover you have to configure the directory where *nyx* will search for dynamic
plugin libraries. *nyx* tries to load every `.so` plugin file on startup.

```yaml
# where to look for plugin files
nyx:
    plugin_dir: /var/lib/nyx/plugins

# as plugins may require some config values
# the whole 'plugins' key/values are passed
# to every successfully loaded plugin
plugins:
    test_key: value
```

Every C plugin needs to contain at least the `plugin_init` function that is
expected to return a non-zero return code:

```c
int
plugin_init(plugin_manager_t *manager)
{
    return 1;
}

```

You can have a look in the [/plugins/][plugins] subdirectory of this repository
to see some example plugins.


## Maintainer

The project is written by Gregor Uhlenheuer. You can reach me at
[kongo2002@gmail.com][mail]


## License

*nyx* is licensed under the [Apache license][apache], Version 2.0

> Unless required by applicable law or agreed to in writing, software
> distributed under the License is distributed on an "AS IS" BASIS,
> WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
> See the License for the specific language governing permissions and
> limitations under the License.


[plugins]: https://github.com/kongo2002/nyx/tree/master/plugins/
[travis]: https://travis-ci.org/kongo2002/nyx/
[god]: https://github.com/mojombo/god/
[mail]: mailto:kongo2002@gmail.com
[apache]: http://www.apache.org/licenses/LICENSE-2.0
[yaml]: http://www.yaml.org/
[docker]: https://www.docker.com/
[supervisor]: http://supervisord.org/
[systemd]: https://github.com/systemd/systemd/
[ansible]: https://www.ansible.com/
