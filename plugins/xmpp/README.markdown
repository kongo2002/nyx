
# XMPP plugin

This plugin enables XMPP notifications of state changes using the `libstrophe`
library.


## Configuration

You may need something along these lines in your *nyx* YAML configuration file
to enable notifications towards a specified user (`xmpp_recipient`):

```yaml
watches:
    # some watches
    # ...

nyx:
    plugin_dir: /some/where

plugins:
    xmpp_jid: nyx@my.xmpp.server/nyx
    xmpp_password: secret
    xmpp_host: 127.0.0.1
    xmpp_recipient: admin@my.xmpp.server
```


### Group chat

It is possible for the *nyx* XMPP plugin to post into a configured group chat as
well:

```yaml
plugins:
    xmpp_jid: nyx@my.xmpp.server/nyx
    xmpp_password: secret
    xmpp_host: 127.0.0.1
    xmpp_groupchat: chat@conference.my.xmpp.server
```
