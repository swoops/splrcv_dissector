/* packet-splrcv.c
 * Routines for Splunk Reciever dissection
 * Copyright 2022, bemodtwz <dennis@hurricanelabs.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * Splunk can injest logs from a forwarder through a reciever port. This
 * disector handles should parse the traffic to a Splunk reciever. This
 * protocol does not appear to be public. All the code here is based off
 * observation and reverse engeneering. Currently this implementation is not
 * 100%. Additionally, the protocol has undergone changes in the past, it will
 * likely have changes in the future too without public notice. So this code is
 * not likely to stay up to date. So no garentee this works at all.
 */

#include <config.h>

#define SPL_DEBUG_IT

#define DEBUG_MSG(x,pinfo) printf()
#else
#define DEBUG_MSG(x) do {} while(0)
#endif

#include <stdio.h> // XXX DEBUG ONLY
#include <epan/packet.h>   /* Should be first Wireshark include (other than config.h) */
#include <epan/expert.h>   /* Include only as needed */
#include <epan/prefs.h>    /* Include only as needed */
#include <epan/ptvcursor.h> /* cursor */

/* Prototypes */
/* (Required to prevent [-Wmissing-prototypes] warnings */
void proto_reg_handoff_splrcv(void);
void proto_register_splrcv(void);

#define SIGVERLEN 0x80
#define SIGHOSTLEN 0x100
#define SIGPORTLEN 0x10
#define SIGLEN SIGVERLEN + SIGHOSTLEN + SIGPORTLEN

/* Initialize the protocol and registered fields */
static gboolean splrcv_desegment = TRUE;
static int proto_splrcv = -1;
static int hf_sigver_field = -1;
static int hf_sighost_field = -1;
static int hf_sigport_field = -1;
static int hf_strlen_field = -1;
static int hf_trad_len_field = -1;
static int hf_trad_kvlen_field = -1;
static int hf_trad_key_field = -1;
static int hf_trad_val_field = -1;
static int hf_trad_list_len_field = -1;
static int hf_trad_list_elm_field = -1;
static int hf_trad_type_field = -1;
static int hf_timezone_field = -1;
static int hf_opcode_field = -1;
static int hf_source_field = -1;
static int hf_host_field = -1;
static int hf_source_type_field = -1;
static int hf_channel_field = -1;
static int hf_dynch_field = -1;
static int hf_type_info_field = -1;
static int hf_channel_code_field = -1;
static int hf_event_flags_field = -1;
static int hf_stimid_field = -1;
static int hf_offset_field = -1;
static int hf_suboffsetflags_field = -1;
static int hf_lastid_field = -1;
static int hf_event_time_field = -1;
static int hf_event_field_cnt_field = -1;
static int hf_eventfield_type_field = -1;
static int hf_eventfield_key_field = -1;
static int hf_eventfield_value_field = -1;
static int hf_event_data_field = -1;
static int hf_zlibsize_field = -1;
static int hf_str_array_len_field = -1;

static int hf_unkown_int_field = -1;

/* return codes for string functions */
#define SPL_DESEG DESEGMENT_ONE_MORE_SEGMENT
#define SPL_ERR -1
#define SPL_OK 0
/* SPL_DESEG aka DESEGMENT_ONE_MORE_SEGMENT is likely greater than zero, but just in case it changes, we handle it in particular */
#define REQ_DESEG(X) (X > 0 || X == SPL_DESEG)
/* desegment string returns >0 value with number of chars still needed */

/* Global sample preference ("controls" display of numbers) */
#define SPLRCV_TCP_PORT 9997
#define SPL_MAX_LEN 0x4000000
#define SPL_MAX_ARRAY_LEN 0x100

typedef enum {
    SPL_32_HEX,
    SPL_32_DEC,
    SPL_64_HEX,
    SPL_64_DEC,
}spl_encoding;

enum packet_type_t {
    // new opcodes
    OP_NEW_CHAN = -8,
    OP_START_ZLIB,
    OP_NEG_6,
    OP_NEG_5,
    OP_START_EVENT,
    OP_CHANNEL_END,
    OP_RESET_CHANNEL,
    OP_TIMEZONE = -1,
    SPL_SIG, SPL_TRAD, SPL_BAD
};

/* Initialize the subtree pointers */
static gint ett_splrcv = -1;
static gint ett_kvfields = -1;
static gint ett_string = -1;
static gint ett_array = -1;

static gint
dissect_leb128(tvbuff_t *tvb, gint offset, guint64 *value)
{
    guint  start_offset = offset;
    guint  shift = 0;
    guint8 byte;

    *value = 0;

    do {
        if ((guint) offset >= tvb_captured_length(tvb)) {
            return 0; // need more bytes
        }
        byte = tvb_get_guint8(tvb, offset);
        offset += 1;

        *value |= ((guint64)(byte & 0x7F) << shift);
        shift += 7;
    } while ((byte & 0x80) && (shift < 64));

    if (byte & 0x80) {
        *value = 0;
        return -1; // invalid
    }

    return offset - start_offset;
}

static inline int
cursor_caplen(ptvcursor_t *cursor)
{
    return tvb_captured_length(ptvcursor_tvbuff(cursor));
}

static inline int
cursor_space_left(ptvcursor_t *cursor)
{
    return cursor_caplen(cursor) - ptvcursor_current_offset(cursor);
}

static inline gint
cursor_fin(ptvcursor_t *cursor)
{
    gint offset = ptvcursor_current_offset(cursor);
    ptvcursor_free(cursor);
    return offset;
}

static inline void
cursor_advance_end(ptvcursor_t *cursor)
{
    ptvcursor_advance(cursor, cursor_space_left(cursor));
}

static inline int
cursor_peek_leb128(ptvcursor_t *cursor, int *numlen, guint64 *value)
{
    *numlen = dissect_leb128(
        ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor),
        value);
    if (*numlen > 0) return SPL_OK;
    if (*numlen == 0) return SPL_DESEG;
    return SPL_ERR;
}

static inline void
cursor_add_num(ptvcursor_t *cursor, int len, guint64 value, int field, spl_encoding enc)
{
    tvbuff_t *tvb = ptvcursor_tvbuff(cursor);
    gint offset = ptvcursor_current_offset(cursor);
    proto_tree *tree = ptvcursor_tree(cursor);
    switch (enc) {
        case SPL_32_HEX:
            proto_tree_add_uint_format_value(tree, field, tvb, offset, len, value, "0x%lx", value);
            break;
        case SPL_32_DEC:
            proto_tree_add_uint_format_value(tree, field, tvb, offset, len, value, "%ld", value);
            break;
        case SPL_64_HEX:
            proto_tree_add_uint64_format_value(tree, field, tvb, offset, len, value, "0x%lx", value);
            break;
        case SPL_64_DEC:
            proto_tree_add_uint64_format_value(tree, field, tvb, offset, len, value, "%ld", value);
            break;
    }
    ptvcursor_advance(cursor, len);
}

static gint64
cursor_add_leb128(ptvcursor_t *cursor, int field, guint64 *ret_value, spl_encoding enc)
{
    int numlen;
    guint64 value;
    int ret = cursor_peek_leb128(cursor, &numlen, &value);
    if (ret == SPL_OK) {
        cursor_add_num(cursor, numlen, value, field, enc);
        if (ret_value) {
            *ret_value = value;
        }
    }
    return ret;
}

static inline void
cursor_add_int_anotate(ptvcursor_t *cursor, int len, guint64 value, int field, const char *anote, int hex)
{
    const char *fmt = "%ld (%s)";
    if (hex) {
        fmt = "0x%lx (%s)";
    }

    proto_tree_add_int_format_value(
        ptvcursor_tree(cursor), field,
        ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor),
        len, value, fmt, value, anote);
    ptvcursor_advance(cursor, len);
}

static inline guint32
cursor_peek_big32(ptvcursor_t *cursor)
{
    return tvb_get_guint32(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor), ENC_BIG_ENDIAN);
}

static inline gint8
cursor_peek_byte(ptvcursor_t *cursor)
{
    return tvb_get_gint8(ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor));
}

static inline int
cursor_lebstr_helper(ptvcursor_t *cursor, int field, int wut)
{
    guint64 len;
    int ret = cursor_add_leb128(cursor, hf_strlen_field, &len, SPL_32_DEC);
    if (ret != SPL_OK) return ret;
    if (wut) len--;
    if (len > SPL_MAX_LEN) return SPL_ERR;

    ret = (int) len - cursor_space_left(cursor);
    if (ret > 0) return ret;

    ptvcursor_add(cursor, field, len, ENC_UTF_8);
    return SPL_OK;
}

static inline int
cursor_add_lebstr_why(ptvcursor_t *cursor, int field)
{
    return cursor_lebstr_helper(cursor, field, 1);
}

static inline int
cursor_add_lebstr(ptvcursor_t *cursor, int field)
{
    return cursor_lebstr_helper(cursor, field, 0);
}

static int
cursor_add_big32_str(ptvcursor_t *cursor, int field)
{
    guint32 len;
    if (cursor_space_left(cursor) < 4) {
        return SPL_DESEG;
    }
    ptvcursor_add_ret_uint(cursor, hf_strlen_field, 4, ENC_BIG_ENDIAN, &len);
    if ((guint32) cursor_space_left(cursor) < len) {
        return len - cursor_space_left(cursor);
    }
    ptvcursor_add(cursor, field, len, ENC_UTF_8);
    return SPL_OK;
}

static gint64
add_leb128_str_array(ptvcursor_t *cursor, int field)
{
    int ret, numlen;
    guint64 i, arrlen;

    ret = cursor_peek_leb128(cursor, &numlen, &arrlen);
    if (ret != SPL_OK) return REQ_DESEG(ret)? SPL_DESEG : ret;

    ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_array, "String Array size: %ld", arrlen);
    cursor_add_num(cursor, numlen, arrlen, hf_unkown_int_field, SPL_64_HEX);
    for (i=0; i < arrlen && ret == SPL_OK; i++) {
        ret = cursor_add_lebstr(cursor, field);
    }
    ptvcursor_pop_subtree(cursor);

    /* don't request exact amount of bytes unless on last field */
    if (REQ_DESEG(ret) && arrlen > 0 && i != arrlen - 1) {
        ret = SPL_DESEG;
    }

    return ret;
}

static int
packet_type(ptvcursor_t *cursor)
{
    gint8 byte = cursor_peek_byte(cursor);
    if (byte < 0 && byte >= -8) { // new packet opcode
        return byte;
    } else if (byte == '-') {
        return SPL_SIG;
    } else {
        guint32 len = cursor_peek_big32(cursor);
        if (len < SPL_MAX_LEN) {
            return SPL_TRAD;
        }
    }
    return SPL_BAD;
}

static int
dissect_signature(ptvcursor_t *cursor, packet_info *pinfo)
{
    int diff, ver = -1;
    gint len;
    const guint8 *str;

    diff = SIGLEN - cursor_space_left(cursor);
    if (diff > 0) {
        return diff;
    }

    str = tvb_get_const_stringz(
        ptvcursor_tvbuff(cursor), ptvcursor_current_offset(cursor),
        &len);
    if (len > SIGVERLEN || len == 0 || !str) return SPL_ERR;

    if (!strcmp(str, "--splunk-cooked-mode-v3--")) {
        ver = 3;
    } else if (!strcmp(str, "--splunk-cooked-mode-v2--")) {
        ver = 2;
    } else if (!strcmp(str, "--splunk-cooked-mode-v2--:C")) {
        ver = 2;
    } else if (!strcmp(str, "--splunk-cooked-mode--")) {
        ver = 1;
    } else {
        return SPL_ERR;
    }

    col_add_fstr(pinfo->cinfo, COL_INFO, "Signature v%d", ver);

    ptvcursor_add_with_subtree(cursor, proto_splrcv, SIGLEN, ENC_NA, ett_splrcv);
    ptvcursor_add(cursor, hf_sigver_field, SIGVERLEN, ENC_UTF_8);
    ptvcursor_add(cursor, hf_sighost_field, SIGHOSTLEN, ENC_UTF_8);
    ptvcursor_add(cursor, hf_sigport_field, SIGPORTLEN, ENC_UTF_8);
    ptvcursor_pop_subtree(cursor);

    return SPL_OK;
}

static int
dissect_trad_event(ptvcursor_t *cursor, packet_info *pinfo)
{
    int ret;
    gint value, i;

    ptvcursor_add_with_subtree(cursor, proto_splrcv, SUBTREE_UNDEFINED_LENGTH, ENC_NA, ett_splrcv);
    printf("[%d] in trad event!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n", pinfo->num);
    col_set_str(pinfo->cinfo, COL_INFO, "Traditional Event");

    /* packet size */
    if (cursor_space_left(cursor) < 4) {
        /* first of two places to return a reassemble request */
        ptvcursor_pop_subtree(cursor);
        return SPL_DESEG;
    }

    ptvcursor_add_ret_uint(cursor, hf_trad_len_field, 4, ENC_BIG_ENDIAN, &value);
    ret = value - cursor_space_left(cursor);
    if (ret > 0) {
        /* last of two places to return a reassemble request */
        ptvcursor_pop_subtree(cursor);
        return ret;
    }

    /* now lack of packet size implies malformed packet */
    ret = SPL_ERR;

    /* number of kv fields */
    if (cursor_space_left(cursor) < 4) goto finish;
    ptvcursor_add_ret_uint(cursor, hf_trad_kvlen_field, 4, ENC_BIG_ENDIAN, &value);

    for (i=0; i < value; i++) {
        ret = cursor_add_big32_str(cursor, hf_trad_key_field);
        if (ret != SPL_OK) goto finish;
        ret = cursor_add_big32_str(cursor, hf_trad_val_field);
        if (ret != SPL_OK) goto finish;
    }

    /* list parsing */
    ret = SPL_ERR;
    if (cursor_space_left(cursor) < 4) goto finish;
    ptvcursor_add_ret_uint(cursor, hf_trad_kvlen_field, 4, ENC_BIG_ENDIAN, &value);

    for (i=0; i < value; i++) {
        ret = cursor_add_big32_str(cursor, hf_trad_len_field);
        if (ret != SPL_OK) goto finish;
    }

    ret = cursor_add_big32_str(cursor, hf_trad_type_field);

finish:
    ptvcursor_pop_subtree(cursor);
    if (ret != SPL_OK) {
        ret = SPL_ERR;
    }
    return ret;
}

static const char *
type_to_str(int op)
{
    switch (op) {
        case OP_NEW_CHAN:
            return "Op -8";
        case OP_START_ZLIB:
            return "Start ZLib Compression";
        case OP_NEG_6:
            return "Op -6";
        case OP_NEG_5:
            return "Op -5";
        case OP_START_EVENT:
            return "Start Event";
        case OP_CHANNEL_END:
            return "End Channel";
        case OP_RESET_CHANNEL:
            return "Reset Channel";
        case OP_TIMEZONE:
            return "Timezone";
        case SPL_SIG:
            return "Splunk Signature";
        case SPL_TRAD:
            return "Splunk Traditional Event";
        default:
            return "Unkown opcode";
    }

}

static int
set_opcode(ptvcursor_t *cursor, packet_info *pinfo, int op)
{
    int byte = cursor_peek_byte(cursor);
    const char *opname = type_to_str(op);
    const gchar *s;
    if (byte != op) {
        printf("Opcode NOT: %d, it's %d\n", op, byte);
        return SPL_ERR;
    }
    printf("[%d] OP '%s' at offset: 0x%x\n", pinfo->num, opname, ptvcursor_current_offset(cursor));

    ptvcursor_add_with_subtree(cursor, proto_splrcv, SUBTREE_UNDEFINED_LENGTH, ENC_NA, ett_splrcv);

    s = col_get_text(pinfo->cinfo, COL_INFO);
    if (!s || !s[0]) {
        printf("[%d] current info is empty\n", pinfo->num);
        col_add_str(pinfo->cinfo, COL_INFO, opname);
    } else {
        printf("[%d] current info is %s\n", pinfo->num, s);
        col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", opname);
    }

    cursor_add_int_anotate(cursor, 1, byte, hf_opcode_field, opname, 0);
    return SPL_OK;
}

static inline int
spl_add_chan_code(ptvcursor_t *cursor, packet_info *pinfo)
{
    guint64 value;
    int ret = cursor_add_leb128(cursor, hf_channel_code_field, &value, SPL_64_DEC);
    if (ret == SPL_OK) {
        col_append_fstr(pinfo->cinfo, COL_INFO, " %ld", value);
    }
    return ret;
}

static int
finish_chan_deets(ptvcursor_t *cursor, packet_info *pinfo)
{
    /* channel code */
    int ret = spl_add_chan_code(cursor, pinfo);
    if (ret != SPL_OK) return REQ_DESEG(ret)? SPL_DESEG : ret;

    /* source */
    ret = cursor_add_lebstr_why(cursor, hf_source_field);
    if (ret != SPL_OK) return REQ_DESEG(ret)? SPL_DESEG : ret;

    /* host */
    ret = cursor_add_lebstr_why(cursor, hf_host_field);
    if (ret != SPL_OK) return REQ_DESEG(ret)? SPL_DESEG : ret;

    /* type */
    ret = cursor_add_lebstr_why(cursor, hf_source_type_field);
    if (ret != SPL_OK) return REQ_DESEG(ret)? SPL_DESEG : ret;

    /* channel */
    ret = cursor_add_lebstr_why(cursor, hf_channel_field);
    if (ret != SPL_OK) return REQ_DESEG(ret)? SPL_DESEG : ret;

    /* string array */
    return add_leb128_str_array(cursor, hf_dynch_field);
}

static int
dissect_new_channel(ptvcursor_t *cursor, packet_info *pinfo)
{
    int ret = set_opcode(cursor, pinfo, OP_NEW_CHAN);
    if (ret != SPL_OK) return ret; /* no subtree */

    ret = cursor_add_leb128(cursor, hf_type_info_field, NULL, SPL_64_DEC);
    if (ret == SPL_OK) {
        ret = finish_chan_deets(cursor, pinfo);
    }

    ptvcursor_pop_subtree(cursor);
    return ret;
}

static int
dissect_start_zlib(ptvcursor_t *cursor, packet_info *pinfo)
{
    int ret = set_opcode(cursor, pinfo, OP_START_ZLIB);
    if (ret == SPL_OK) {
        ret = cursor_add_leb128(cursor, hf_zlibsize_field, NULL, SPL_64_HEX);
    }
    ptvcursor_pop_subtree(cursor);

    /* TODO disect it */
    return ret;
}

static int
dissect_neg6(ptvcursor_t *cursor, packet_info *pinfo)
{
    int ret = set_opcode(cursor, pinfo, OP_NEG_6);
    if (ret != SPL_OK) return ret;

    ret = cursor_add_leb128(cursor, hf_unkown_int_field, NULL, SPL_64_HEX);
    if (ret == SPL_OK) {
        ret = cursor_add_leb128(cursor, hf_unkown_int_field, NULL, SPL_64_HEX);
    }
    ptvcursor_pop_subtree(cursor);
    return ret;
}

static int
dissect_neg5(ptvcursor_t *cursor, packet_info *pinfo)
{
    int ret = set_opcode(cursor, pinfo, OP_NEG_5);
    if (ret == SPL_OK) {
        ret = cursor_add_leb128(cursor, hf_unkown_int_field, NULL, SPL_64_HEX);
        ptvcursor_pop_subtree(cursor);
    }
    return ret;
}

static int
dissect_start_event(ptvcursor_t *cursor, packet_info *pinfo)
{
    int ret, end = 0;
    guint64 count, flags;


    ret = set_opcode(cursor, pinfo, OP_START_EVENT);
    if (ret != SPL_OK) return ret;

    /* channel code */
    ret = spl_add_chan_code(cursor, pinfo);
    if (ret != SPL_OK) goto finish;

    /* flags */
    /* TODO: show flags big fields in a tree */
    ret = cursor_add_leb128(cursor, hf_event_flags_field, &flags, SPL_64_HEX);
    if (ret != SPL_OK) goto finish;

    if (flags & 2) {
        /* stimid */
        ret = cursor_add_leb128(cursor, hf_stimid_field, NULL, SPL_64_HEX);
        if (ret != SPL_OK) goto finish;

        /* offset */
        ret = cursor_add_leb128(cursor, hf_offset_field, NULL, SPL_64_HEX);
        if (ret != SPL_OK) goto finish;

        /* suboffset */
        ret = cursor_add_leb128(cursor, hf_suboffsetflags_field, NULL, SPL_64_HEX);
        if (ret != SPL_OK) goto finish;
    }

    if (flags & 4) {
        /* lastid */
        ret = cursor_add_leb128(cursor, hf_lastid_field, NULL, SPL_64_HEX);
        if (ret != SPL_OK) goto finish;
    }

    if (flags & 8) {
        /* EventTime */
        ret = cursor_add_leb128(cursor, hf_event_time_field, NULL, SPL_64_HEX);
        if (ret != SPL_OK) goto finish;
    }


     { /* key value stuff */
        guint64 i;
        int numlen;
        ret = cursor_peek_leb128(cursor, &numlen, &count);
        if (ret != SPL_OK) goto finish;
        ptvcursor_add_text_with_subtree(cursor, SUBTREE_UNDEFINED_LENGTH, ett_kvfields, "Fields count: %ld", count);
        cursor_add_num(cursor, numlen, count, hf_event_field_cnt_field, SPL_64_HEX);


        for (i = 0; i < count; i++) {
            ret = cursor_add_leb128(cursor, hf_eventfield_type_field, NULL, SPL_64_HEX);
            if (ret != SPL_OK) break;

            ret = cursor_add_lebstr(cursor, hf_eventfield_key_field);
            if (ret != SPL_OK) break;

            ret = cursor_add_lebstr(cursor, hf_eventfield_value_field);
            if (ret != SPL_OK) break;
        }
    }
    ptvcursor_pop_subtree(cursor);
    if (ret != SPL_OK) goto finish;

    /* Event data */
    end++; /* last field so if we know how much more we need, return that */
    ret = cursor_add_lebstr(cursor, hf_event_data_field);

finish:
    if (!end && REQ_DESEG(ret)) {
        ret = SPL_DESEG;
    }
    ptvcursor_pop_subtree(cursor);
    return ret;
}

static int
dissect_chan_end(ptvcursor_t *cursor, packet_info *pinfo)
{
    int ret = set_opcode(cursor, pinfo, OP_CHANNEL_END);
    if (ret == SPL_OK) {
        ret = spl_add_chan_code(cursor, pinfo);
        ptvcursor_pop_subtree(cursor);
    }
    return ret;
}

static int
dissect_reset_chan(ptvcursor_t *cursor, packet_info *pinfo)
{
    int ret = set_opcode(cursor, pinfo, OP_RESET_CHANNEL);
    if (ret == SPL_OK) {
        ret = finish_chan_deets(cursor, pinfo);
        ptvcursor_pop_subtree(cursor);
    }
    return ret;
}

static int
dissect_timezone(ptvcursor_t *cursor, packet_info *pinfo)
{
    int ret = set_opcode(cursor, pinfo, OP_TIMEZONE);
    if (ret == SPL_OK) {
        ret = cursor_add_lebstr(cursor, hf_timezone_field);
        ptvcursor_pop_subtree(cursor);
    }
    return ret;
}


/* Code to actually dissect the packets */
static int
dissect_splrcv(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        void *data _U_)
{
    int pdustart = 0;
    int ret;
    ptvcursor_t *cursor = ptvcursor_new(pinfo->pool, tree, tvb, pdustart);

    /* Check that the packet is long enough for it to belong to us. */
    if (tvb_captured_length(tvb) < 32)
        return 0;

    /* set info column */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "splrcv");
    col_clear(pinfo->cinfo, COL_INFO);

    ret = SPL_OK;
    while (ret == SPL_OK && cursor_space_left(cursor) > 0) {
        int type = packet_type(cursor);
        pdustart = ptvcursor_current_offset(cursor); /* for desegment */
        printf("[%d] %s at 0x%x\n", pinfo->num, type_to_str(type), pdustart);
        switch (type) {
            case SPL_SIG:
                ret = dissect_signature(cursor, pinfo);
                break;
            case SPL_TRAD:
                ret = dissect_trad_event(cursor, pinfo);
                break;
            case OP_NEW_CHAN:
                ret = dissect_new_channel(cursor, pinfo);
                break;
            case OP_START_ZLIB:
                ret = dissect_start_zlib(cursor, pinfo);
                break;
            case OP_NEG_6:
                ret = dissect_neg6(cursor, pinfo);
                break;
            case OP_NEG_5:
                ret = dissect_neg5(cursor, pinfo);
                break;
            case OP_START_EVENT:
                ret = dissect_start_event(cursor, pinfo);
                break;
            case OP_CHANNEL_END:
                ret = dissect_chan_end(cursor, pinfo);
                break;
            case OP_RESET_CHANNEL:
                ret = dissect_reset_chan(cursor, pinfo);
                break;
            case OP_TIMEZONE:
                ret = dissect_timezone(cursor, pinfo);
                break;
            default:
                ret = SPL_ERR;
                break;
        }
    }

    if (ret != SPL_OK) {
        if (REQ_DESEG(ret)) {
            if (splrcv_desegment && pinfo->can_desegment) {
                pinfo->desegment_offset = pdustart;
                pinfo->desegment_len = ret;
            }
        } else {
            // ERROR
            printf("[%d] got error %d\n", pinfo->num, ret);
            ptvcursor_free(cursor);
            return 0;
        }
    }

    /* debug only*/
    printf("[%d] splrcv returning 0x%x from 0x%x\n", pinfo->num, ptvcursor_current_offset(cursor), tvb_captured_length(tvb));
    if (pinfo->desegment_len != 0) {
        if (pinfo->desegment_len == SPL_DESEG) {
            printf("[%d] splrcv reassemble offset: 0x%x len: SPL_DESEG\n", pinfo->num, pinfo->desegment_offset);
        } else {
            printf("[%d] splrcv reassemble offset: 0x%x len: 0x%x\n", pinfo->num, pinfo->desegment_offset, pinfo->desegment_len);
        }
    }

    return cursor_fin(cursor);
}

/* Register the protocol with Wireshark.
 *
 * This format is required because a script is used to build the C function that
 * calls all the protocol registration.
 */
void
proto_register_splrcv(void)
{
    /* Setup list of header fields  See Section 1.5 of README.dissector for
     * details. */
    static hf_register_info hf[] = {
        { &hf_sigver_field,
          { "Signature version", "splrcv.sig.ver", FT_STRINGZPAD, BASE_NONE, NULL, 0x0,
             "NULL", HFILL }
        },
        { &hf_sighost_field,
          { "Forwarder hostname", "splrcv.sig.host", FT_STRINGZPAD, BASE_NONE, NULL, 0x0,
             "NULL", HFILL }
        },
        { &hf_sigport_field,
          { "Forwarder port", "splrcv.sig.port", FT_STRINGZPAD, BASE_NONE, NULL, 0x0,
             "NULL", HFILL }
        },
        { &hf_strlen_field,
          { "Length", "splrcv.strlen", FT_UINT32, BASE_HEX, NULL, 0x0,
             "NULL", HFILL }
        },
        { &hf_trad_len_field,
          { "Length", "splrcv.old.len", FT_UINT32, BASE_HEX, NULL, 0x0,
             "NULL", HFILL }
        },
        { &hf_trad_kvlen_field,
          { "Number of key value pairs", "splrcv.trad.kvlen", FT_UINT32, BASE_HEX, NULL, 0x0,
             "NULL", HFILL }
        },
        { &hf_trad_key_field,
          { "Key", "splrcv.tradkey", FT_STRINGZ, BASE_NONE, NULL, 0x0,
             "NULL", HFILL }
        },
        { &hf_trad_val_field,
          { "Value", "splrcv.tradval", FT_STRINGZ, BASE_NONE, NULL, 0x0,
             "NULL", HFILL }
        },
        { &hf_trad_list_len_field,
          { "Number of elements in list", "splrcv.oldlist.len", FT_UINT32, BASE_HEX, NULL, 0x0,
             "NULL", HFILL }
        },
        { &hf_trad_list_elm_field,
          { "Element in list", "splrcv.oldval", FT_STRINGZ, BASE_NONE, NULL, 0x0,
             "NULL", HFILL }
        },
        { &hf_trad_type_field,
          { "Type of packet", "splrcv.type", FT_STRINGZ, BASE_NONE, NULL, 0x0,
             "NULL", HFILL }
        },
        { &hf_timezone_field,
          { "Timezone info", "splrcv.timezone", FT_STRINGZ, BASE_NONE, NULL, 0x0,
             "NULL", HFILL }
        },
        { &hf_opcode_field,
          { "Opcode", "splrcv.opcode", FT_INT8, BASE_DEC, NULL, 0x0,
             "NULL", HFILL }
        },
        { &hf_source_field,
          { "Source", "splrcv.src", FT_STRINGZ, BASE_NONE, NULL, 0x0,
             "NULL", HFILL }
        },
        { &hf_host_field,
          { "Host", "splrcv.timezone", FT_STRINGZ, BASE_NONE, NULL, 0x0,
             "NULL", HFILL }
        },
        { &hf_source_type_field,
          { "Source Type", "splrcv.srctype", FT_STRINGZ, BASE_NONE, NULL, 0x0,
             "NULL", HFILL }
        },
        { &hf_channel_field,
          { "Channel", "splrcv.chan_str", FT_STRINGZ, BASE_NONE, NULL, 0x0,
             "NULL", HFILL }
        },
        { &hf_dynch_field,
          { "Dynch", "splrcv.dynch", FT_STRINGZ, BASE_NONE, NULL, 0x0,
             "NULL", HFILL }
        },
        { &hf_type_info_field,
          { "Channel", "splrcv.typeinfo", FT_UINT64, BASE_DEC, NULL, 0x0,
             "NULL", HFILL }
        },
        { &hf_channel_code_field, /* combine hf_channel_field somehow */
          { "Channel", "splrcv.chan", FT_UINT64, BASE_DEC, NULL, 0x0,
             "NULL", HFILL }
        },
        { &hf_event_flags_field,
          { "Flags", "splrcv.event_flags", FT_UINT64, BASE_DEC, NULL, 0x0,
             "NULL", HFILL }
        },
        { &hf_stimid_field,
          { "Stimeid", "splrcv.stimid", FT_UINT64, BASE_DEC, NULL, 0x0,
             "NULL", HFILL }
        },
        { &hf_offset_field,
          { "Offset", "splrcv.event_offset", FT_UINT64, BASE_DEC, NULL, 0x0,
             "NULL", HFILL }
        },
        { &hf_suboffsetflags_field,
          { "Suboffset", "splrcv.event_suboffset", FT_UINT64, BASE_DEC, NULL, 0x0,
             "NULL", HFILL }
        },
        { &hf_lastid_field,
          { "Lastid", "splrcv.lastid", FT_UINT64, BASE_DEC, NULL, 0x0,
             "NULL", HFILL }
        },
        { &hf_event_time_field,
          { "Event Time", "splrcv.eventtime", FT_UINT64, BASE_DEC, NULL, 0x0,
             "NULL", HFILL }
        },
        { &hf_event_field_cnt_field,
          { "Number of fields", "splrcv.event_field_cnt", FT_UINT64, BASE_DEC, NULL, 0x0,
             "NULL", HFILL }
        },
        { &hf_eventfield_type_field,
          { "Typeflag", "splrcv.eventfield.type", FT_UINT64, BASE_DEC, NULL, 0x0,
             "NULL", HFILL }
        },
        { &hf_eventfield_key_field,
          { "key", "splrcv.eventtime.key", FT_STRING, BASE_NONE, NULL, 0x0,
             "NULL", HFILL }
        },
        { &hf_eventfield_value_field,
          { "value", "splrcv.eventtime.value", FT_STRING, BASE_NONE, NULL, 0x0,
             "NULL", HFILL }
        },
        { &hf_event_data_field,
          { "Data", "splrcv.eventtime.data", FT_STRING, BASE_NONE, NULL, 0x0,
             "NULL", HFILL }
        },
        { &hf_zlibsize_field,
          { "Typeflag", "splrcv.zlibsize", FT_UINT64, BASE_HEX, NULL, 0x0,
             "NULL", HFILL }
        },
        { &hf_str_array_len_field,
          { "String Array Len", "splrcv.str_array_len", FT_UINT64, BASE_DEC, NULL, 0x0,
             "NULL", HFILL }
        },
        { &hf_unkown_int_field,
          { "Meaning Uknown", "splrcv.unkown_int", FT_UINT64, BASE_DEC, NULL, 0x0,
             "NULL", HFILL }
        },
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_splrcv, &ett_kvfields, &ett_string, &ett_array,
    };

    /* Register the protocol name and description */
    proto_splrcv = proto_register_protocol("Splunk Reciever", "splrcv", "splrcv");

    /* Required function calls to register the header fields and subtrees */
    proto_register_field_array(proto_splrcv, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}


/* Simpler form of proto_reg_handoff_splrcv which can be used if there are
 * no prefs-dependent registration function calls. */
void
proto_reg_handoff_splrcv(void)
{
    dissector_handle_t splrcv_handle;
    module_t *splrcv_module;
    /* Use create_dissector_handle() to indicate that dissect_splrcv()
     * returns the number of bytes it dissected (or 0 if it thinks the packet
     * does not belong to Splunk Reciever).
     */
    splrcv_handle = create_dissector_handle(dissect_splrcv, proto_splrcv);
    dissector_add_uint_with_preference("tcp.port", SPLRCV_TCP_PORT, splrcv_handle);

    splrcv_module = prefs_register_protocol(proto_splrcv, NULL);
    prefs_register_bool_preference(splrcv_module, "desegment",
                                  "Re-assemble Splunk Reciever packets that span multiple tcp packets",
                                  "Re-assemble Splunk Reciever packets that span multiple tcp packets",
                                  &splrcv_desegment);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
