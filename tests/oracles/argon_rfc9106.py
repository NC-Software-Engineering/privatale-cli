# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 NC Software Engineering
#
# This file is part of privatale-cli.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, version 3.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
"""Official RFC9106 section 5.3 KAT, independently evaluated by libargon2.
The AMK wrapper never accepts these secret/AD/low-memory test parameters.
"""
import ctypes as c
import ctypes.util

def check():
    class Context(c.Structure):
        _fields_=[('out',c.c_void_p),('outlen',c.c_uint32),('pwd',c.c_void_p),('pwdlen',c.c_uint32),('salt',c.c_void_p),('saltlen',c.c_uint32),('secret',c.c_void_p),('secretlen',c.c_uint32),('ad',c.c_void_p),('adlen',c.c_uint32),('t_cost',c.c_uint32),('m_cost',c.c_uint32),('lanes',c.c_uint32),('threads',c.c_uint32),('version',c.c_uint32),('allocate_cbk',c.c_void_p),('free_cbk',c.c_void_p),('flags',c.c_uint32)]
    out=c.create_string_buffer(32);pwd=c.create_string_buffer(bytes([1])*32);salt=c.create_string_buffer(bytes([2])*16);secret=c.create_string_buffer(bytes([3])*8);ad=c.create_string_buffer(bytes([4])*12)
    ptr=lambda b:c.cast(b,c.c_void_p)
    context=Context(ptr(out),32,ptr(pwd),32,ptr(salt),16,ptr(secret),8,ptr(ad),12,3,32,4,4,0x13,None,None,0)
    lib=c.CDLL(ctypes.util.find_library('argon2'));fn=lib.argon2_ctx;fn.argtypes=[c.POINTER(Context),c.c_int];fn.restype=c.c_int
    if fn(c.byref(context),2)!=0:raise RuntimeError('argon2_ctx failed')
    assert out.raw.hex()=='0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659'
