import ycm_core

def FlagsForFile(filename, **kwargs):
    flags = [ '-Wall'
            , '-Wextra'
            , '-I.'
            , '-std=gnu89'
            ]

    return {'flags': flags, 'do_cache': True}
