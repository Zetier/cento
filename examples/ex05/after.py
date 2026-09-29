#!/usr/bin/env python3
# Copyright (c) 2026 Zetier
# SPDX-License-Identifier: Apache-2.0
# mpkt-msg, mapped to cento: the same MPKX status message as before.py, byte for
# byte (run check.py and see). before.py's shouting comments -- "RECOMPUTE BOTH
# every single time you touch ANY byte" -- are reducers here: every length and
# the CRC derive from the spans they describe on every emit, so no edit can
# leave one stale. The session token is a symbol the handshake binds at send.
import cento

MAGIC = 0x4D504B58  # "MPKX": MPKT's TLV extension message
MSG_TLV_EXT = 0x0102  # version 1, type 2
REC_SIZE = 0x10
PAY_OFF = 0x8  # payload words start here, inside each record


class TlvHdr(cento.View, size=0xC):
    magic: cento.u32
    msg_type: cento.u16
    total_len: cento.u16
    crc: cento.u32


class TlvRecord(cento.View, size=REC_SIZE):
    rtype: cento.u16
    flags: cento.u16
    payload_len: cento.u16
    resv: cento.u16
    pay0: cento.u32
    pay1: cento.u32


layout = cento.Layout(endian="big")  # big-endian, fill 0x00: the MK-1 wire facts
msg = layout.region("msg", max_size=len(TlvHdr) + 3 * REC_SIZE)
hdr = msg.at(0x0, TlvHdr, name="hdr")
recs = msg.at(len(hdr), TlvRecord * 3, name="recs")

hdr.magic = MAGIC
hdr.msg_type = MSG_TLV_EXT
recs[0].rtype = 0x0001  # CAPS
recs[0].pay0 = 0x00010003  # proto 1.3
recs[1].rtype = 0x0002  # AUTH
recs[1].flags = 0x8000  # TOKEN_PRESENT
recs[1].pay0 = layout.sym("session_token")  # the live handshake supplies it
recs[1].pay1 = 0x4D4B2D31  # "MK-1"
recs[2].rtype = 0x0003  # ECHO
recs[2].pay0 = 0x41414141
recs[2].pay1 = 0x42424242

# One source of truth for every length: each record's payload_len derives from
# ITS OWN payload span, total_len and the CRC from the whole records span.
for i in range(len(recs)):
    recs[i].payload_len = cento.length(msg[recs[i].offset + PAY_OFF : recs[i].offset + REC_SIZE])
hdr.total_len = cento.length(recs)
hdr.crc = cento.crc32_mpeg2(recs)

if __name__ == "__main__":
    layout.bind("session_token", 0x5EC0DE42, source="handshake")
    print(f"after tlv: {layout.image('msg').hex()}")
