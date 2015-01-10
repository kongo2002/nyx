
# nyx

*nyx* is a lean process monitoring tool written in *C*.

[![build status](https://api.travis-ci.org/kongo2002/nyx.svg)][travis]

The project is inspired by [god][god] - the great ruby process monitor.


## Usage


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
- `start <watch>`: send a start command to the specified watch
- `stop <watch>`: send a stop command to the specified watch
- `terminate`: terminate the nyx daemon


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
