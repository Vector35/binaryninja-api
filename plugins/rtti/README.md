# C++ RTTI

Parses and symbolizes C++ RTTI information in [Binary Ninja].

## Exposed Metadata

This plugin will store metadata on the view queryable view the `rtti` key.

### Example Metadata

```pycon
>>> pprint.pp(bv.auto_metadata['rtti'])
{'classes': {'4294983728': {'className': 'ParentA',
                            'processor': 1,
                            'vft': {'address': 4294983784}},
             '4294983744': {'bases': [{'className': 'ParentA',
                                       'classOffset': 0,
                                       'vft': {'address': 4294983784}}],
                            'className': 'SomeClass',
                            'processor': 1,
                            'vft': {'address': 4294983712}},
             '4294983864': {'className': 'ParentB',
                            'processor': 1,
                            'vft': {'address': 4294983952}},
             '4294983880': {'bases': [{'className': 'ParentA',
                                       'classOffset': 0,
                                       'vft': {'address': 4294983784}},
                                      {'className': 'ParentB',
                                       'classOffset': 16,
                                       'vft': {'address': 4294983952}}],
                            'className': 'MultiSomeClass',
                            'processor': 1,
                            'vft': {'address': 4294983848}}}}
```

[Binary Ninja]: https://binary.ninja