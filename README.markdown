
# nyx

*nyx* is a lean process monitoring tool written in *C*.

[![build status](https://api.travis-ci.org/kongo2002/nyx.svg)][travis]

The project is inspired by [god][god] - the great ruby process monitor.


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


### Command interface

You can interact with a running *nyx* daemon instance using the same executable:

```bash
$ nyx version
<<< version
>>> 0.0.1

```

Right now the following commands are implemented:

- `ping`: ping a running daemon
- `version`: return the daemon version
- `status <watch>`: get the status of the specified watch
- `start <watch>`: send a start command to the specified watch
- `stop <watch>`: send a stop command to the specified watch
- `restart <watch>`: send a restart command to the specified watch
- `history <watch>`: get the latest events of the specified watch
- `watches`: get all currently configured watches
- `reload`: reload the nyx configuration
- `terminate`: terminate the nyx daemon
- `quit`: stop the nyx daemon and all watched processes


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


[travis]: https://travis-ci.org/kongo2002/nyx/
[god]: https://github.com/mojombo/god/
[mail]: mailto:kongo2002@gmail.com
[apache]: http://www.apache.org/licenses/LICENSE-2.0
[yaml]: http://www.yaml.org/
[docker]: https://www.docker.com/
