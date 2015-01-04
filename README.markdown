
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


### Command interface

You can interact with a running *nyx* daemon instance with the same executable:

```bash
$ nyx version
0.0.1

```

At the moment available commands are:

    - `ping`: ping a running daemon
    - `version`: return the daemon version
    - `start <watch>`: send a start command to the specified watch
    - `stop <watch>`: send a stop command to the specified watch
    - `terminate`: terminate the god daemon


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
