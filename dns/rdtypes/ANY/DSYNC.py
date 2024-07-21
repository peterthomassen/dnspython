# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

import struct

import dns.immutable
import dns.rdata
import dns.rdatatype
import dns.rdtypes.util


@dns.immutable.immutable
class DSYNC(dns.rdata.Rdata):
    """DSYNC record"""

    # see: draft-ietf-dnsop-generalized-notify

    __slots__ = ["rrtype", "scheme", "port", "target"]

    def __init__(self, rdclass, rdtype, rrtype, scheme, port, target):
        super().__init__(rdclass, rdtype)
        self.rrtype = self._as_uint16(rrtype)
        self.scheme = self._as_uint8(scheme)
        self.port = self._as_uint16(port)
        self.target = self._as_name(target)

    def to_text(self, origin=None, relativize=True, **kw):
        target = self.target.choose_relativity(origin, relativize)
        return "%s %d %d %s" % (
            dns.rdatatype.to_text(self.rrtype),
            self.scheme,
            self.port,
            target,
        )

    @classmethod
    def from_text(
        cls, rdclass, rdtype, tok, origin=None, relativize=True, relativize_to=None
    ):
        rrtype = dns.rdatatype.from_text(tok.get_string())
        scheme = tok.get_uint8()
        port = tok.get_uint16()
        target = tok.get_name(origin, relativize, relativize_to)
        return cls(rdclass, rdtype, rrtype, scheme, port, target)

    def _to_wire(self, file, compress=None, origin=None, canonicalize=False):
        three_ints = struct.pack("!HBH", self.rrtype, self.scheme, self.port)
        file.write(three_ints)
        # TODO Compression disallowed. Do we need to explicitly turn it off?
        self.target.to_wire(file, compress, origin, canonicalize)

    @classmethod
    def from_wire_parser(cls, rdclass, rdtype, parser, origin=None):
        (rrtype, scheme, port) = parser.get_struct("!HBH")
        target = parser.get_name(origin)
        return cls(rdclass, rdtype, rrtype, scheme, port, target)
