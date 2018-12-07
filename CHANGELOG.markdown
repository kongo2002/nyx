# CHANGELOG


## 1.9.5

2018-12-07

* improvement: add `--local` to command mode
* improvement: slight delay after daemon initialization


## 1.9.4

2018-10-21

* feature: nyx in `--passive` mode does not start services automatically on
  startup
* improvement: nyx will try to create the folders of the `log_file` and
  `error_file` settings if necessary


## 1.9.3

2018-10-16

* feature: `--local` launches the nyx daemon in a directory-local mode that is
  based on the current working directory and evaluates all configured paths
  relative to that directory
* internal: prevent access to nyx's own pid
* internal: more thorough resource handling in forker subprocess


## 1.9.2

2018-05-22

* feature: stop-commands receive the `$NYX_PID` environment variable to access
  the PID of the process that is about to be terminated


## 1.9.1

2018-03-26

* bug: fix OSX build


## 1.9.0

2018-03-26

* improvement: ability to trigger state changes in 'flapping' processes
* improvement: faster quit behavior
* internal: process state changes in a per-process queue


## 1.8.0

2017-11-07

* feature: multiple config files
  possibility to pass a directory of config files to `-c`
* improvement: more robust parsing of malformed config files


## 1.7.1

2017-06-13

* improvement: faster state thread termination


## 1.7.0

2017-05-22

* feature: support for environment variable substitution in config files
  (e.g. `PATH: "$PATH:/usr/local/bin"`)
* improvement: faster restart behavior due to process stats like CPU and memory
* improvement: transport error codes via connector communication
* internal: support very long connector responses


## 1.6.1

2017-02-09

* feature: add `startup_delay` configuration
* improvement: more sophisticated "string-command" parsing


## 1.6.0

2017-02-04

* feature: support for state change commands for `all` watches
* internal: introduce separate 'forker' process that handles process spawning


## 1.5.0

2016-11-30

* improvement: exponential delay for 'flapping' processes
* internal: more elaborate state change logging
* internal: comply with c99 standard


## 1.4.0

2015-11-01

* feature: OSX support
* feature: configurable nyx log file
* feature: add ad-hoc watch via `--run`
* plugins: add example mail plugin
* improvement: dedicated error codes
* internal: timeout for state thread termination


## 1.3.0

2015-05-07

* feature: support for configurable HTTP connector (see `http_port`)
* plugins: add example XMPP plugin
* internal: extend plugin architecture
* internal: replace `sleep` usages with `select`


## 1.2.0

2015-04-01

* feature: add support for https checks (using OpenSSL)
* feature: add `config` command


## 1.1.0

2015-03-29

* feature: add plugin architecture (+ example plugin)


## 1.0.0

2015-03-14

* first stable release
