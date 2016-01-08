import ycm_core

def FlagsForFile(filename, **kwargs):
    flags = [ '-Wall'
            , '-Wextra'
            , '-I.'
            , '-std=c99'
            ]

    return {'flags': flags, 'do_cache': True}
