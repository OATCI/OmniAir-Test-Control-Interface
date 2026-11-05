/*
 * OmniAir OmniTap — Reference Header-Only C99 COER Encoder & pcapng Writer
 *
 * Purpose:
 *   Demonstrates why byte-aligned ASN.1 COER (ITU-T X.696) + pcapng EPB Custom Binary Option 2989
 *   was selected for OmniTap:
 *     - Zero bit-shifting across byte boundaries (all integer fields are 1, 2, 4, or 8 octets).
 *     - Tiny code size (~2 KB compiled) with zero external library dependencies.
 *     - Supports both OmniTap (Native, EPB Option 2989 / 0x0BAD) and OmniTap-Lua (Custom Block
 *       0x00000BAD) via a 6-line toggle at the packet-write boundary.
 *
 * Placeholder Note:
 *   OMNITAP_PEN_PLACEHOLDER (32473) is the RFC 5612 documentation PEN used until a production PEN
 *   is assigned (see 00-OmniTap-Registrations.md).
 */

#ifndef OMNITAP_COER_H
#define OMNITAP_COER_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#define OMNITAP_VERSION_MAJOR        1u
#define OMNITAP_VERSION_MINOR        0u
#define OMNITAP_PEN_PLACEHOLDER      32473u      /* RFC 5612 documentation PEN placeholder */

/* pcapng block and option constants */
#define PCAPNG_BT_SHB                0x0A0D0D0Au
#define PCAPNG_BT_IDB                0x00000001u
#define PCAPNG_BT_EPB                0x00000006u
#define PCAPNG_BT_CUSTOM_COPY        0x00000BADu
#define PCAPNG_OPT_ENDOFOPT          0u
#define PCAPNG_OPT_EPB_FLAGS         2u
#define PCAPNG_OPT_EPB_PACKETID      5u
#define PCAPNG_OPT_CUSTOM_BIN_COPY   2989u       /* 0x0BAD: copyable Custom Binary Option */

/* COER CHOICE tags for OmniTapObjectBody (root alternatives 0..3) */
#define OMNITAP_CHOICE_CAPTURE       0x80u
#define OMNITAP_CHOICE_IF_CONTEXT    0x81u
#define OMNITAP_CHOICE_PACKET_META   0x82u
#define OMNITAP_CHOICE_SUPP_RESULT   0x83u

/* Big-endian network byte order writers (for ASN.1 COER payloads) */
static inline void omnitap_put_be16(uint8_t *dst, uint16_t v) {
    dst[0] = (uint8_t)(v >> 8);
    dst[1] = (uint8_t)(v);
}

static inline void omnitap_put_be32(uint8_t *dst, uint32_t v) {
    dst[0] = (uint8_t)(v >> 24);
    dst[1] = (uint8_t)(v >> 16);
    dst[2] = (uint8_t)(v >> 8);
    dst[3] = (uint8_t)(v);
}

/*
 * Write the 5-octet COER OmniTapObject header:
 *   octet 0: 0x00 (OmniTapObject preamble: extension bit = 0)
 *   octet 1: 0x00 (OmniTapProfileVersion preamble: extension bit = 0)
 *   octet 2: major (1)
 *   octet 3: minor (0)
 *   octet 4: body CHOICE tag (0x80..0x83)
 */
static inline size_t omnitap_coer_put_header(uint8_t *buf, uint8_t choice_tag) {
    buf[0] = 0x00u;
    buf[1] = 0x00u;
    buf[2] = OMNITAP_VERSION_MAJOR;
    buf[3] = OMNITAP_VERSION_MINOR;
    buf[4] = choice_tag;
    return 5u;
}

/*
 * Encode a minimal COER(OmniTapObject) with body = capture (0x80) carrying the 128-bit sessionId.
 * Returns total encoded COER byte length (22 octets).
 */
static inline size_t omnitap_coer_encode_capture_context(
    uint8_t *buf,
    const uint8_t session_id[16]
) {
    size_t pos = omnitap_coer_put_header(buf, OMNITAP_CHOICE_CAPTURE);
    buf[pos++] = 0x00u; /* OmniTapCaptureContext preamble: ext=0, all 4 OPTIONAL strings absent */
    memcpy(buf + pos, session_id, 16u);
    return pos + 16u;
}

/*
 * Optional WGS-84 observer position + 1-antenna RSSI/RSRP/SINR observation for fast C encoding.
 */
typedef struct {
    int      has_wgs84_position;
    int32_t  latitude_e7;           /* -900000000..900000000 */
    int32_t  longitude_e7;          /* -1799999999..1800000000 */
    int16_t  altitude_dm;           /* -4096..32767 decimeters (V2X and A2X) */
    int      has_radio_freq_bw;
    uint32_t center_freq_khz;       /* 0..100000000 kHz */
    uint32_t bandwidth_khz;         /* 1..100000 kHz */
} omnitap_fast_packet_meta_t;

/*
 * Encode COER(OmniTapObject) with body = packetMetadata (0x82).
 * Demonstrates byte-aligned COER encoding without any bit-stream state machine.
 */
static inline size_t omnitap_coer_encode_packet_metadata(
    uint8_t *buf,
    uint32_t session_tag,
    uint32_t record_id,
    const omnitap_fast_packet_meta_t *opt
) {
    size_t pos = omnitap_coer_put_header(buf, OMNITAP_CHOICE_PACKET_META);
    uint8_t preamble = 0x00u;
    if (opt != NULL) {
        if (opt->has_wgs84_position) {
            preamble |= 0x10u; /* bit 3 (0x10): observerLocation present */
        }
        if (opt->has_radio_freq_bw) {
            preamble |= 0x08u; /* bit 4 (0x08): radio present */
        }
    }
    buf[pos++] = preamble;
    omnitap_put_be32(buf + pos, record_id);
    pos += 4u;
    omnitap_put_be32(buf + pos, session_tag);
    pos += 4u;

    if (opt != NULL && opt->has_wgs84_position) {
        /* ObserverLocation preamble: ext=0, hepeCm=0, vpeCm=0, ageUs=0, motion=0 */
        buf[pos++] = 0x00u;
        /* GeographicPosition preamble: ext=0, altitudeDm=1 (bit 1 -> 0x40) */
        buf[pos++] = 0x40u;
        /* coordinateReferenceSystem: wgs84 (0) */
        buf[pos++] = 0x00u;
        omnitap_put_be32(buf + pos, (uint32_t)opt->latitude_e7);
        pos += 4u;
        omnitap_put_be32(buf + pos, (uint32_t)opt->longitude_e7);
        pos += 4u;
        omnitap_put_be16(buf + pos, (uint16_t)opt->altitude_dm);
        pos += 2u;
    }

    if (opt != NULL && opt->has_radio_freq_bw) {
        /*
         * RadioObservation preamble (1 ext bit + 9 optional bits = 10 bits -> 2 octets):
         *   centerFrequencyKHz is optional #7 (octet 0 bit 7 = 0x01)
         *   bandwidthKHz       is optional #8 (octet 1 bit 0 = 0x80)
         */
        buf[pos++] = 0x01u;
        buf[pos++] = 0x80u;
        omnitap_put_be32(buf + pos, opt->center_freq_khz);
        pos += 4u;
        omnitap_put_be32(buf + pos, opt->bandwidth_khz);
        pos += 4u;
    }

    return pos;
}

/*
 * Write a copyable pcapng Custom Block (0x00000BAD) carrying PEN + coer_buf.
 */
static inline int pcapng_write_custom_block(
    FILE *fp,
    uint32_t pen,
    const uint8_t *coer_buf,
    size_t coer_len
) {
    static const uint8_t zero_pad[4] = {0, 0, 0, 0};
    size_t pad_len = (4u - (coer_len & 3u)) & 3u;
    uint32_t btype = PCAPNG_BT_CUSTOM_COPY;
    uint32_t total_len = (uint32_t)(16u + coer_len + pad_len);

    if (fwrite(&btype, 4, 1, fp) != 1 ||
        fwrite(&total_len, 4, 1, fp) != 1 ||
        fwrite(&pen, 4, 1, fp) != 1 ||
        fwrite(coer_buf, 1, coer_len, fp) != coer_len ||
        (pad_len > 0 && fwrite(zero_pad, 1, pad_len, fp) != pad_len) ||
        fwrite(&total_len, 4, 1, fp) != 1) {
        return -1;
    }
    return 0;
}

/*
 * Write a standard pcapng Enhanced Packet Block (EPB) with epb_packetid (option 5)
 * and optional OmniTap Native PacketMetadata in Custom Binary Option 2989 (0x0BAD).
 */
static inline int pcapng_write_epb(
    FILE *fp,
    uint32_t interface_id,
    uint64_t ts_utc,
    const uint8_t *pkt_bytes,
    uint32_t pkt_len,
    uint64_t epb_packetid,
    uint32_t pen,
    const uint8_t *meta_buf,
    size_t meta_len
) {
    static const uint8_t zero_pad[4] = {0, 0, 0, 0};
    size_t pkt_pad = (4u - (pkt_len & 3u)) & 3u;
    size_t meta_val_len = (meta_buf != NULL && meta_len > 0) ? (4u + meta_len) : 0u;
    size_t meta_pad = (4u - (meta_val_len & 3u)) & 3u;

    /* Options: epb_packetid (12 B) + optional Option 2989 + opt_endofopt (4 B) */
    size_t opts_len = 12u + (meta_val_len > 0 ? (4u + meta_val_len + meta_pad) : 0u) + 4u;
    uint32_t btype = PCAPNG_BT_EPB;
    uint32_t total_len = (uint32_t)(32u + pkt_len + pkt_pad + opts_len);
    uint32_t ts_high = (uint32_t)(ts_utc >> 32);
    uint32_t ts_low  = (uint32_t)(ts_utc & 0xFFFFFFFFu);
    uint16_t opt_pid_hdr[2] = {PCAPNG_OPT_EPB_PACKETID, 8u};
    uint16_t opt_end_hdr[2] = {PCAPNG_OPT_ENDOFOPT, 0u};

    if (fwrite(&btype, 4, 1, fp) != 1 ||
        fwrite(&total_len, 4, 1, fp) != 1 ||
        fwrite(&interface_id, 4, 1, fp) != 1 ||
        fwrite(&ts_high, 4, 1, fp) != 1 ||
        fwrite(&ts_low, 4, 1, fp) != 1 ||
        fwrite(&pkt_len, 4, 1, fp) != 1 ||
        fwrite(&pkt_len, 4, 1, fp) != 1 ||
        fwrite(pkt_bytes, 1, pkt_len, fp) != pkt_len ||
        (pkt_pad > 0 && fwrite(zero_pad, 1, pkt_pad, fp) != pkt_pad) ||
        fwrite(opt_pid_hdr, 2, 2, fp) != 2 ||
        fwrite(&epb_packetid, 8, 1, fp) != 1) {
        return -1;
    }

    if (meta_val_len > 0) {
        uint16_t opt_meta_hdr[2] = {PCAPNG_OPT_CUSTOM_BIN_COPY, (uint16_t)meta_val_len};
        if (fwrite(opt_meta_hdr, 2, 2, fp) != 2 ||
            fwrite(&pen, 4, 1, fp) != 1 ||
            fwrite(meta_buf, 1, meta_len, fp) != meta_len ||
            (meta_pad > 0 && fwrite(zero_pad, 1, meta_pad, fp) != meta_pad)) {
            return -1;
        }
    }

    if (fwrite(opt_end_hdr, 2, 2, fp) != 2 ||
        fwrite(&total_len, 4, 1, fp) != 1) {
        return -1;
    }
    return 0;
}

/*
 * Write one packet + its COER(OmniTapObject) PacketMetadata in either:
 *   - OmniTap (Native, omnitap_lua_mode == 0): attaches meta_buf to EPB as Custom Binary Option 2989
 *   - OmniTap-Lua      (omnitap_lua_mode != 0): writes standalone Custom Block (0x00000BAD) before EPB
 */
static inline int omnitap_write_packet(
    FILE *fp,
    int omnitap_lua_mode,
    uint32_t pen,
    uint32_t interface_id,
    uint64_t ts_utc,
    const uint8_t *pkt_bytes,
    uint32_t pkt_len,
    uint64_t epb_packetid,
    const uint8_t *meta_buf,
    size_t meta_len
) {
    if (omnitap_lua_mode) {
        /* OmniTap-Lua: write standalone copyable Custom Block (0x00000BAD) immediately before EPB */
        if (pcapng_write_custom_block(fp, pen, meta_buf, meta_len) != 0) {
            return -1;
        }
        return pcapng_write_epb(fp, interface_id, ts_utc, pkt_bytes, pkt_len, epb_packetid, pen, NULL, 0);
    } else {
        /* OmniTap Native (default): attach meta_buf to EPB as Custom Binary Option 2989 (0x0BAD) */
        return pcapng_write_epb(fp, interface_id, ts_utc, pkt_bytes, pkt_len, epb_packetid, pen, meta_buf, meta_len);
    }
}

#ifdef __cplusplus
}
#endif

#endif /* OMNITAP_COER_H */
