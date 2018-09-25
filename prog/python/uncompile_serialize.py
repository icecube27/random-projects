#!/usr/bin/env python
#
# Simple code which shows how to decompile
# Python code using uncompyle module and 
# marshal for serialization
#
# Author : icecube27

import marshal, uncompyle6, sys

def f(n):
    if n == 0:
        return 1
    else:
        return n * f(n-1)

def dump_serialized_fn_code(fn_name):
    if fn_name in globals():
        return marshal.dumps(globals()[fn_name].func_code)
    else:
        return None

def disass_fn(fn_name):
    s_fn_code = dump_serialized_fn_code(fn_name)
    if s_fn_code:
        fn_code = marshal.loads(s_fn_code)
        uncompyle6.main.decompile(2.7, fn_code, sys.stdout)

if __name__ == "__main__":
    disass_fn("f")
