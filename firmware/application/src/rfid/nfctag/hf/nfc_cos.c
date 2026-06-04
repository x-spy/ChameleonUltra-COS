/**
 * @file nfc_cos.c
 * @brief ISO14443-4 CPU-card-like COS emulation.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <stdlib.h>
#include <string.h>

#include "app_status.h"
#include "fds_util.h"
#include "nfc_cos.h"
#include "tag_persistence.h"
#include "utils.h"

#define NRF_LOG_MODULE_NAME nfc_cos
#include "nrf_log.h"
#include "nrf_log_ctrl.h"
#include "nrf_log_default_backends.h"
NRF_LOG_MODULE_REGISTER();

#define NFC_COS_MAGIC       0x434F5331u /* "COS1" */
#define NFC_COS_VERSION     1u
#define NFC_COS_FID_MF      0x3F00u
#define NFC_COS_INVALID_IDX 0xFFu

#define SW_SUCCESS                 0x9000u
#define SW_WARNING_EOF             0x6282u
#define SW_WRONG_LENGTH            0x6700u
#define SW_COMMAND_INCOMPATIBLE    0x6981u
#define SW_SECURITY_NOT_SATISFIED  0x6982u
#define SW_WRITE_DISABLED          0x6985u
#define SW_NO_CURRENT_EF           0x6986u
#define SW_FILE_NOT_FOUND          0x6A82u
#define SW_RECORD_NOT_FOUND        0x6A83u
#define SW_NOT_ENOUGH_MEMORY       0x6A84u
#define SW_INCORRECT_P1P2          0x6A86u
#define SW_INS_NOT_SUPPORTED       0x6D00u
#define SW_CLA_NOT_SUPPORTED       0x6E00u

/* ISO14443-4 PCB constants. */
#define PCB_IBLOCK_MASK     0xC0
#define PCB_IBLOCK_VAL      0x00
#define PCB_CID_FOLLOWING   0x10
#define PCB_NAD_FOLLOWING   0x08
#define PCB_CHAIN           0x20
#define PCB_BLOCK_NUM       0x01
#define PCB_SBLOCK_VAL      0xC0
#define PCB_SBLOCK_WTX      0x30
#define PCB_SBLOCK_DESELECT 0xC2
#define WTX_VALUE           0x3B

typedef struct {
    uint8_t lc;
    uint8_t raw_le;
    uint16_t le;
    bool has_lc;
    bool has_le;
    const uint8_t *data;
} cos_apdu_case_t;

typedef enum {
    COS_EF_RES_OK,
    COS_EF_RES_BAD_P1P2,
    COS_EF_RES_NO_CURRENT,
    COS_EF_RES_FILE_NOT_FOUND,
    COS_EF_RES_WRONG_TYPE,
} cos_ef_res_t;

static nfc_cos_information_t *m_info = NULL;
static nfc_tag_14a_coll_res_reference_t m_shadow_coll_res;

static uint8_t m_selected_df = 0;
static uint8_t m_selected_ef = NFC_COS_INVALID_IDX;
static uint8_t m_challenge[32];
static uint8_t m_challenge_len = 0;

static uint8_t m_block_num = 0;
static bool m_cid_supported = false;
static uint8_t m_cid = 0;
static uint8_t m_resp_buf[NFC_COS_MAX_APDU];
static uint8_t m_tx_buf[NFC_COS_MAX_APDU + 4];
static uint8_t m_scratch_pool[NFC_COS_DATA_POOL_SIZE];

static inline uint16_t be16(const uint8_t *p) {
    return ((uint16_t)p[0] << 8) | p[1];
}

static inline void put_be16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static uint16_t append_sw(uint8_t *resp, uint16_t len, uint16_t resp_max, uint16_t sw) {
    if (resp_max < 2) return 0;
    if (len + 2 > resp_max) len = resp_max - 2;
    resp[len++] = (uint8_t)(sw >> 8);
    resp[len++] = (uint8_t)sw;
    return len;
}

static uint16_t sw_only(uint8_t *resp, uint16_t resp_max, uint16_t sw) {
    return append_sw(resp, 0, resp_max, sw);
}

static uint16_t sw_correct_length(uint8_t *resp, uint16_t resp_max, uint16_t len) {
    if (len > 256) return sw_only(resp, resp_max, SW_WRONG_LENGTH);
    return sw_only(resp, resp_max, (uint16_t)(0x6C00u | (len == 256 ? 0x00 : (len & 0xFF))));
}

static bool is_df_type(uint8_t type) {
    return type == NFC_COS_FILE_TYPE_MF || type == NFC_COS_FILE_TYPE_DF;
}

static bool is_ef_type(uint8_t type) {
    return type == NFC_COS_FILE_TYPE_EF_BINARY || type == NFC_COS_FILE_TYPE_EF_RECORD;
}

static uint8_t find_file_by_fid(uint16_t fid) {
    if (m_info == NULL) return NFC_COS_INVALID_IDX;
    for (uint8_t i = 0; i < NFC_COS_MAX_FILES; i++) {
        if (m_info->files[i].active && m_info->files[i].fid == fid) return i;
    }
    return NFC_COS_INVALID_IDX;
}

static uint8_t find_child_by_fid(uint16_t parent_fid, uint16_t fid, uint8_t wanted_type) {
    if (m_info == NULL) return NFC_COS_INVALID_IDX;
    for (uint8_t i = 0; i < NFC_COS_MAX_FILES; i++) {
        nfc_cos_file_entry_t *e = &m_info->files[i];
        if (!e->active || e->parent_fid != parent_fid || e->fid != fid) continue;
        if (wanted_type != 0 && e->type != wanted_type) continue;
        return i;
    }
    return NFC_COS_INVALID_IDX;
}

static uint8_t find_ef_by_sfi(uint16_t parent_fid, uint8_t sfi, uint8_t wanted_type) {
    if (m_info == NULL || sfi == 0) return NFC_COS_INVALID_IDX;
    for (uint8_t i = 0; i < NFC_COS_MAX_FILES; i++) {
        nfc_cos_file_entry_t *e = &m_info->files[i];
        if (!e->active || e->parent_fid != parent_fid || e->sfi != sfi) continue;
        if (!is_ef_type(e->type)) continue;
        if (wanted_type != 0 && e->type != wanted_type) continue;
        return i;
    }
    return NFC_COS_INVALID_IDX;
}

static uint8_t find_df_by_aid(const uint8_t *aid, uint8_t aid_len) {
    if (m_info == NULL || aid_len == 0) return NFC_COS_INVALID_IDX;
    for (uint8_t i = 0; i < NFC_COS_MAX_FILES; i++) {
        nfc_cos_file_entry_t *e = &m_info->files[i];
        if (!e->active || !is_df_type(e->type) || e->aid_len != aid_len) continue;
        if (memcmp(e->aid, aid, aid_len) == 0) return i;
    }
    return NFC_COS_INVALID_IDX;
}

static uint8_t first_free_file(void) {
    if (m_info == NULL) return NFC_COS_INVALID_IDX;
    for (uint8_t i = 0; i < NFC_COS_MAX_FILES; i++) {
        if (!m_info->files[i].active) return i;
    }
    return NFC_COS_INVALID_IDX;
}

static uint16_t record_count(const nfc_cos_file_entry_t *e) {
    if (e->type != NFC_COS_FILE_TYPE_EF_RECORD || e->data_len == 0) return 0;
    uint16_t off = 0;
    uint16_t count = 0;
    while (off + 2 <= e->data_len) {
        uint16_t len = be16(&m_info->data_pool[e->data_offset + off]);
        if (off + 2 + len > e->data_len) break;
        off += 2 + len;
        count++;
    }
    return count;
}

static uint16_t record_payload_len(const nfc_cos_file_entry_t *e) {
    if (e->type != NFC_COS_FILE_TYPE_EF_RECORD || e->data_len == 0) return 0;
    uint16_t off = 0;
    uint16_t total = 0;
    while (off + 2 <= e->data_len) {
        uint16_t len = be16(&m_info->data_pool[e->data_offset + off]);
        if (off + 2 + len > e->data_len) break;
        total += len;
        off += 2 + len;
    }
    return total;
}

static bool find_record(const nfc_cos_file_entry_t *e, uint8_t record_no,
                        uint16_t *record_off, uint16_t *record_len) {
    if (e == NULL || e->type != NFC_COS_FILE_TYPE_EF_RECORD || record_no == 0) return false;
    uint16_t off = 0;
    uint8_t current = 1;
    while (off + 2 <= e->data_len) {
        uint16_t len = be16(&m_info->data_pool[e->data_offset + off]);
        if (off + 2 + len > e->data_len) break;
        if (current == record_no) {
            if (record_off != NULL) *record_off = off;
            if (record_len != NULL) *record_len = len;
            return true;
        }
        off += 2 + len;
        current++;
    }
    return false;
}

static bool compact_pool_with_resize(uint8_t resize_idx, uint16_t new_alloc_len) {
    if (m_info == NULL) return false;
    uint16_t used = 0;
    memset(m_scratch_pool, 0, sizeof(m_scratch_pool));

    for (uint8_t i = 0; i < NFC_COS_MAX_FILES; i++) {
        nfc_cos_file_entry_t *e = &m_info->files[i];
        if (!e->active || !is_ef_type(e->type)) continue;
        uint16_t alloc_len = (i == resize_idx) ? new_alloc_len : e->alloc_len;
        if (alloc_len == 0) {
            e->data_offset = 0;
            e->alloc_len = 0;
            continue;
        }
        if ((uint32_t)used + alloc_len > NFC_COS_DATA_POOL_SIZE) return false;
        uint16_t copy_len = e->data_len;
        if (copy_len > alloc_len) copy_len = alloc_len;
        if (copy_len > 0) {
            memcpy(&m_scratch_pool[used], &m_info->data_pool[e->data_offset], copy_len);
        }
        e->data_offset = used;
        e->alloc_len = alloc_len;
        if (e->data_len > alloc_len) e->data_len = alloc_len;
        used += alloc_len;
    }

    memcpy(m_info->data_pool, m_scratch_pool, sizeof(m_info->data_pool));
    m_info->pool_used = used;
    return true;
}

static bool ensure_file_capacity(uint8_t idx, uint16_t len) {
    nfc_cos_file_entry_t *e = &m_info->files[idx];
    if (len <= e->alloc_len) return true;
    return compact_pool_with_resize(idx, len);
}

static bool has_child(uint16_t parent_fid) {
    if (m_info == NULL) return false;
    for (uint8_t i = 0; i < NFC_COS_MAX_FILES; i++) {
        if (m_info->files[i].active && m_info->files[i].parent_fid == parent_fid) {
            return true;
        }
    }
    return false;
}

static void refresh_file_count(void) {
    if (m_info == NULL) return;
    uint8_t count = 0;
    for (uint8_t i = 0; i < NFC_COS_MAX_FILES; i++) {
        if (m_info->files[i].active) count++;
    }
    m_info->file_count = count;
}

static uint8_t delete_file_recursive(uint16_t fid) {
    uint8_t idx = find_file_by_fid(fid);
    if (idx == NFC_COS_INVALID_IDX) return STATUS_PAR_ERR;
    if (fid == NFC_COS_FID_MF) return STATUS_PAR_ERR;

    while (has_child(fid)) {
        for (uint8_t i = 0; i < NFC_COS_MAX_FILES; i++) {
            if (m_info->files[i].active && m_info->files[i].parent_fid == fid) {
                delete_file_recursive(m_info->files[i].fid);
                break;
            }
        }
    }

    memset(&m_info->files[idx], 0, sizeof(m_info->files[idx]));
    if (m_selected_ef == idx) m_selected_ef = NFC_COS_INVALID_IDX;
    if (m_selected_df == idx) m_selected_df = 0;
    compact_pool_with_resize(NFC_COS_INVALID_IDX, 0);
    refresh_file_count();
    return STATUS_SUCCESS;
}

static void set_factory_coll_res(nfc_cos_information_t *info) {
    info->res_coll.size = NFC_TAG_14A_UID_DOUBLE_SIZE;
    info->res_coll.atqa[0] = 0x04;
    info->res_coll.atqa[1] = 0x00;
    info->res_coll.sak[0] = 0x20;
    info->res_coll.uid[0] = 0x04;
    info->res_coll.uid[1] = 0xC0;
    info->res_coll.uid[2] = 0x5E;
    info->res_coll.uid[3] = 0x00;
    info->res_coll.uid[4] = 0x00;
    info->res_coll.uid[5] = 0x00;
    info->res_coll.uid[6] = 0x01;

    static const uint8_t default_ats[] = {
        0x10, 0x78, 0x80, 0x70, 0x02, 0x00,
        0x31, 0xC1, 0x64, 0x09, 0x97, 0x61,
        0x26, 0x00, 0x90, 0x00
    };
    info->res_coll.ats.length = sizeof(default_ats);
    memcpy(info->res_coll.ats.data, default_ats, sizeof(default_ats));
}

static void set_factory_fs(nfc_cos_information_t *info) {
    memset(info->files, 0, sizeof(info->files));
    memset(info->data_pool, 0, sizeof(info->data_pool));
    info->pool_used = 0;
    info->file_count = 1;

    nfc_cos_file_entry_t *mf = &info->files[0];
    mf->active = 1;
    mf->fid = NFC_COS_FID_MF;
    mf->parent_fid = 0x0000;
    mf->type = NFC_COS_FILE_TYPE_MF;
}

static void ensure_valid_fs(void) {
    if (m_info == NULL) return;
    if (m_info->magic == NFC_COS_MAGIC && m_info->version == NFC_COS_VERSION &&
            m_info->files[0].active && m_info->files[0].fid == NFC_COS_FID_MF) {
        return;
    }

    memset(m_info, 0, sizeof(*m_info));
    m_info->magic = NFC_COS_MAGIC;
    m_info->version = NFC_COS_VERSION;
    m_info->write_enabled = 1;
    set_factory_coll_res(m_info);
    set_factory_fs(m_info);
}

static bool parse_short_apdu(const uint8_t *apdu, uint16_t len, cos_apdu_case_t *parsed) {
    memset(parsed, 0, sizeof(*parsed));
    parsed->le = 0;
    if (len == 4) return true;
    if (len == 5) {
        parsed->has_le = true;
        parsed->raw_le = apdu[4];
        parsed->le = apdu[4] == 0 ? 256 : apdu[4];
        return true;
    }
    if (len < 5) return false;
    uint8_t lc = apdu[4];
    if (lc == 0 || len < (uint16_t)(5 + lc)) return false;
    parsed->has_lc = true;
    parsed->lc = lc;
    parsed->data = &apdu[5];
    if (len == (uint16_t)(5 + lc)) return true;
    if (len == (uint16_t)(6 + lc)) {
        parsed->has_le = true;
        parsed->raw_le = apdu[5 + lc];
        parsed->le = parsed->raw_le == 0 ? 256 : parsed->raw_le;
        return true;
    }
    return false;
}

static uint16_t build_fci(uint8_t idx, uint8_t *resp, uint16_t resp_max) {
    if (resp_max < 2) return 0;
    nfc_cos_file_entry_t *e = &m_info->files[idx];
    uint8_t body[64];
    uint16_t off = 0;

    body[off++] = 0x82;
    body[off++] = 0x01;
    body[off++] = e->type;

    body[off++] = 0x83;
    body[off++] = 0x02;
    put_be16(&body[off], e->fid);
    off += 2;

    if (is_ef_type(e->type)) {
        body[off++] = 0x80;
        body[off++] = 0x02;
        put_be16(&body[off], e->data_len);
        off += 2;
        if (e->sfi != 0) {
            body[off++] = 0x88;
            body[off++] = 0x01;
            body[off++] = e->sfi;
        }
    }

    if (e->aid_len > 0) {
        body[off++] = 0x84;
        body[off++] = e->aid_len;
        memcpy(&body[off], e->aid, e->aid_len);
        off += e->aid_len;
    }

    uint16_t out = 0;
    resp[out++] = 0x6F;
    resp[out++] = (uint8_t)off;
    memcpy(&resp[out], body, off);
    out += off;
    return append_sw(resp, out, resp_max, SW_SUCCESS);
}

static uint16_t apdu_select(const uint8_t *apdu, const cos_apdu_case_t *parsed,
                            uint8_t *resp, uint16_t resp_max) {
    uint8_t p1 = apdu[2];
    uint8_t idx = NFC_COS_INVALID_IDX;

    if (p1 == 0x04) {
        if (!parsed->has_lc || parsed->lc > NFC_COS_MAX_AID_LEN) {
            return sw_only(resp, resp_max, SW_WRONG_LENGTH);
        }
        idx = find_df_by_aid(parsed->data, parsed->lc);
    } else {
        if (!parsed->has_lc || parsed->lc != 2) {
            return sw_only(resp, resp_max, SW_WRONG_LENGTH);
        }
        uint16_t fid = be16(parsed->data);
        if (fid == NFC_COS_FID_MF) {
            idx = 0;
        } else if (p1 == 0x01) {
            idx = find_child_by_fid(m_info->files[m_selected_df].fid, fid, NFC_COS_FILE_TYPE_DF);
        } else if (p1 == 0x02) {
            idx = find_child_by_fid(m_info->files[m_selected_df].fid, fid, 0);
            if (idx != NFC_COS_INVALID_IDX && !is_ef_type(m_info->files[idx].type)) {
                idx = NFC_COS_INVALID_IDX;
            }
        } else if (p1 == 0x00) {
            idx = find_child_by_fid(m_info->files[m_selected_df].fid, fid, 0);
            if (idx == NFC_COS_INVALID_IDX) idx = find_file_by_fid(fid);
        } else {
            return sw_only(resp, resp_max, SW_INCORRECT_P1P2);
        }
    }

    if (idx == NFC_COS_INVALID_IDX) {
        return sw_only(resp, resp_max, SW_FILE_NOT_FOUND);
    }

    if (is_df_type(m_info->files[idx].type)) {
        m_selected_df = idx;
        m_selected_ef = NFC_COS_INVALID_IDX;
    } else {
        m_selected_ef = idx;
    }
    return build_fci(idx, resp, resp_max);
}

static cos_ef_res_t resolve_binary_ef(uint8_t p1, uint8_t p2, uint16_t *offset, uint8_t *out_idx) {
    if (p1 & 0x80) {
        if (p1 & 0x60) return COS_EF_RES_BAD_P1P2;
        uint8_t sfi = p1 & 0x1F;
        if (sfi == 0 || sfi == 0x1F) return COS_EF_RES_BAD_P1P2;
        *offset = p2;
        *out_idx = find_ef_by_sfi(m_info->files[m_selected_df].fid, sfi, 0);
        if (*out_idx == NFC_COS_INVALID_IDX) return COS_EF_RES_FILE_NOT_FOUND;
        return m_info->files[*out_idx].type == NFC_COS_FILE_TYPE_EF_BINARY ?
               COS_EF_RES_OK : COS_EF_RES_WRONG_TYPE;
    }

    *offset = ((uint16_t)p1 << 8) | p2;
    *out_idx = m_selected_ef;
    if (*out_idx == NFC_COS_INVALID_IDX) return COS_EF_RES_NO_CURRENT;
    return m_info->files[*out_idx].type == NFC_COS_FILE_TYPE_EF_BINARY ?
           COS_EF_RES_OK : COS_EF_RES_WRONG_TYPE;
}

static cos_ef_res_t resolve_record_ef(uint8_t p2, bool append_mode, uint8_t *out_idx) {
    uint8_t sfi = p2 >> 3;
    uint8_t mode = p2 & 0x07;

    if (sfi == 0x1F) return COS_EF_RES_BAD_P1P2;
    if (append_mode) {
        if (mode != 0x00) return COS_EF_RES_BAD_P1P2;
    } else if (sfi != 0) {
        if (mode != 0x04) return COS_EF_RES_BAD_P1P2;
    } else if (mode != 0x00 && mode != 0x04) {
        return COS_EF_RES_BAD_P1P2;
    }

    if (sfi != 0) {
        *out_idx = find_ef_by_sfi(m_info->files[m_selected_df].fid, sfi, 0);
        if (*out_idx == NFC_COS_INVALID_IDX) return COS_EF_RES_FILE_NOT_FOUND;
        return m_info->files[*out_idx].type == NFC_COS_FILE_TYPE_EF_RECORD ?
               COS_EF_RES_OK : COS_EF_RES_WRONG_TYPE;
    }

    *out_idx = m_selected_ef;
    if (*out_idx == NFC_COS_INVALID_IDX) return COS_EF_RES_NO_CURRENT;
    return m_info->files[*out_idx].type == NFC_COS_FILE_TYPE_EF_RECORD ?
           COS_EF_RES_OK : COS_EF_RES_WRONG_TYPE;
}

static uint16_t sw_for_ef_res(cos_ef_res_t res, uint8_t *resp, uint16_t resp_max) {
    switch (res) {
        case COS_EF_RES_BAD_P1P2:
            return sw_only(resp, resp_max, SW_INCORRECT_P1P2);
        case COS_EF_RES_NO_CURRENT:
            return sw_only(resp, resp_max, SW_NO_CURRENT_EF);
        case COS_EF_RES_FILE_NOT_FOUND:
            return sw_only(resp, resp_max, SW_FILE_NOT_FOUND);
        case COS_EF_RES_WRONG_TYPE:
            return sw_only(resp, resp_max, SW_COMMAND_INCOMPATIBLE);
        case COS_EF_RES_OK:
        default:
            return sw_only(resp, resp_max, SW_SUCCESS);
    }
}

static uint16_t append_record_data(uint8_t *resp, uint16_t resp_max, const uint8_t *data,
                                   uint16_t len, const cos_apdu_case_t *parsed) {
    if (!parsed->has_le) return sw_only(resp, resp_max, SW_WRONG_LENGTH);
    if (parsed->raw_le != 0 && parsed->le != len) {
        return sw_correct_length(resp, resp_max, len);
    }

    uint16_t out_len = len;
    if (out_len > 256) out_len = 256;
    if (out_len > resp_max - 2) out_len = resp_max - 2;
    memcpy(resp, data, out_len);
    return append_sw(resp, out_len, resp_max, (len > out_len) ? SW_WARNING_EOF : SW_SUCCESS);
}

static uint8_t update_record_by_index(uint8_t idx, uint8_t record_no,
                                      const uint8_t *data, uint16_t data_len,
                                      bool *record_not_found) {
    if (record_not_found != NULL) *record_not_found = false;
    nfc_cos_file_entry_t *e = &m_info->files[idx];
    if (e->type != NFC_COS_FILE_TYPE_EF_RECORD || data == NULL || data_len == 0) {
        return STATUS_PAR_ERR;
    }
    if (e->record_size != 0 && data_len != e->record_size) {
        return STATUS_PAR_ERR;
    }

    uint16_t record_off = 0;
    uint16_t old_record_len = 0;
    if (!find_record(e, record_no, &record_off, &old_record_len)) {
        if (record_not_found != NULL) *record_not_found = true;
        return STATUS_PAR_ERR;
    }

    uint16_t old_entry_len = 2 + old_record_len;
    uint16_t new_entry_len = 2 + data_len;
    uint16_t new_file_len = e->data_len - old_entry_len + new_entry_len;
    if (new_entry_len > old_entry_len && !ensure_file_capacity(idx, new_file_len)) {
        return STATUS_MEM_ERR;
    }

    e = &m_info->files[idx];
    uint8_t *base = &m_info->data_pool[e->data_offset];
    uint16_t old_tail_off = record_off + old_entry_len;
    uint16_t new_tail_off = record_off + new_entry_len;
    uint16_t tail_len = e->data_len - old_tail_off;
    if (old_tail_off != new_tail_off && tail_len > 0) {
        memmove(&base[new_tail_off], &base[old_tail_off], tail_len);
    }
    put_be16(&base[record_off], data_len);
    memcpy(&base[record_off + 2], data, data_len);
    e->data_len = new_file_len;
    return STATUS_SUCCESS;
}

static uint16_t apdu_read_binary(const uint8_t *apdu, const cos_apdu_case_t *parsed,
                                 uint8_t *resp, uint16_t resp_max) {
    if (parsed->has_lc) return sw_only(resp, resp_max, SW_WRONG_LENGTH);

    uint16_t offset = 0;
    uint8_t idx = NFC_COS_INVALID_IDX;
    cos_ef_res_t res = resolve_binary_ef(apdu[2], apdu[3], &offset, &idx);
    if (res != COS_EF_RES_OK) return sw_for_ef_res(res, resp, resp_max);

    nfc_cos_file_entry_t *e = &m_info->files[idx];
    if (offset > e->data_len) return sw_only(resp, resp_max, SW_INCORRECT_P1P2);

    uint16_t le = parsed->has_le ? parsed->le : 256;
    if (le > 256) le = 256;
    if (le > resp_max - 2) le = resp_max - 2;
    uint16_t available = e->data_len - offset;
    uint16_t out_len = le <= available ? le : available;
    if (out_len > 0) memcpy(resp, &m_info->data_pool[e->data_offset + offset], out_len);
    return append_sw(resp, out_len, resp_max, SW_SUCCESS);
}

static uint16_t apdu_update_binary(const uint8_t *apdu, const cos_apdu_case_t *parsed,
                                   uint8_t *resp, uint16_t resp_max) {
    if (!m_info->write_enabled) return sw_only(resp, resp_max, SW_WRITE_DISABLED);
    if (!parsed->has_lc || parsed->has_le) return sw_only(resp, resp_max, SW_WRONG_LENGTH);

    uint16_t offset = 0;
    uint8_t idx = NFC_COS_INVALID_IDX;
    cos_ef_res_t res = resolve_binary_ef(apdu[2], apdu[3], &offset, &idx);
    if (res != COS_EF_RES_OK) return sw_for_ef_res(res, resp, resp_max);

    nfc_cos_file_entry_t *e = &m_info->files[idx];
    if ((uint32_t)offset + parsed->lc > UINT16_MAX) {
        return sw_only(resp, resp_max, SW_NOT_ENOUGH_MEMORY);
    }
    uint16_t new_len = offset + parsed->lc;
    if (!ensure_file_capacity(idx, new_len)) {
        return sw_only(resp, resp_max, SW_NOT_ENOUGH_MEMORY);
    }
    if (offset > e->data_len) {
        memset(&m_info->data_pool[e->data_offset + e->data_len], 0, offset - e->data_len);
    }
    memcpy(&m_info->data_pool[e->data_offset + offset], parsed->data, parsed->lc);
    if (new_len > e->data_len) e->data_len = new_len;
    return sw_only(resp, resp_max, SW_SUCCESS);
}

static uint16_t apdu_read_record(const uint8_t *apdu, const cos_apdu_case_t *parsed,
                                 uint8_t *resp, uint16_t resp_max) {
    if (parsed->has_lc) return sw_only(resp, resp_max, SW_WRONG_LENGTH);

    uint8_t idx = NFC_COS_INVALID_IDX;
    cos_ef_res_t res = resolve_record_ef(apdu[3], false, &idx);
    if (res != COS_EF_RES_OK) return sw_for_ef_res(res, resp, resp_max);

    nfc_cos_file_entry_t *e = &m_info->files[idx];
    uint16_t off = 0;
    uint16_t len = 0;
    if (find_record(e, apdu[2], &off, &len)) {
        return append_record_data(resp, resp_max,
                                  &m_info->data_pool[e->data_offset + off + 2],
                                  len, parsed);
    }
    return sw_only(resp, resp_max, SW_RECORD_NOT_FOUND);
}

static uint16_t apdu_append_record(const uint8_t *apdu, const cos_apdu_case_t *parsed,
                                   uint8_t *resp, uint16_t resp_max) {
    if (!m_info->write_enabled) return sw_only(resp, resp_max, SW_WRITE_DISABLED);
    if (!parsed->has_lc || parsed->has_le) {
        return sw_only(resp, resp_max, SW_WRONG_LENGTH);
    }
    if (apdu[2] != 0x00) return sw_only(resp, resp_max, SW_INCORRECT_P1P2);

    uint8_t idx = NFC_COS_INVALID_IDX;
    cos_ef_res_t res = resolve_record_ef(apdu[3], true, &idx);
    if (res != COS_EF_RES_OK) return sw_for_ef_res(res, resp, resp_max);

    uint8_t st = nfc_cos_append_record(m_info->files[idx].fid, parsed->data, parsed->lc);
    if (st == STATUS_SUCCESS) return sw_only(resp, resp_max, SW_SUCCESS);
    if (st == STATUS_MEM_ERR) return sw_only(resp, resp_max, SW_NOT_ENOUGH_MEMORY);
    return sw_only(resp, resp_max, SW_WRONG_LENGTH);
}

static uint16_t apdu_update_record(const uint8_t *apdu, const cos_apdu_case_t *parsed,
                                   uint8_t *resp, uint16_t resp_max) {
    if (!m_info->write_enabled) return sw_only(resp, resp_max, SW_WRITE_DISABLED);
    if (!parsed->has_lc || parsed->has_le) return sw_only(resp, resp_max, SW_WRONG_LENGTH);

    uint8_t idx = NFC_COS_INVALID_IDX;
    cos_ef_res_t res = resolve_record_ef(apdu[3], false, &idx);
    if (res != COS_EF_RES_OK) return sw_for_ef_res(res, resp, resp_max);

    bool record_not_found = false;
    uint8_t st = update_record_by_index(idx, apdu[2], parsed->data, parsed->lc, &record_not_found);
    if (record_not_found) return sw_only(resp, resp_max, SW_RECORD_NOT_FOUND);
    if (st == STATUS_SUCCESS) return sw_only(resp, resp_max, SW_SUCCESS);
    if (st == STATUS_MEM_ERR) return sw_only(resp, resp_max, SW_NOT_ENOUGH_MEMORY);
    return sw_only(resp, resp_max, SW_WRONG_LENGTH);
}

static uint16_t apdu_get_challenge(const cos_apdu_case_t *parsed,
                                   uint8_t *resp, uint16_t resp_max) {
    uint16_t le = parsed->has_le ? parsed->le : 8;
    if (le > sizeof(m_challenge)) le = sizeof(m_challenge);
    if (le > resp_max - 2) le = resp_max - 2;
    for (uint16_t i = 0; i < le; i++) {
        m_challenge[i] = (uint8_t)(rand() & 0xFF);
    }
    m_challenge_len = (uint8_t)le;
    memcpy(resp, m_challenge, le);
    return append_sw(resp, le, resp_max, SW_SUCCESS);
}

uint16_t nfc_cos_process_apdu(const uint8_t *apdu, uint16_t apdu_len,
                              uint8_t *resp, uint16_t resp_max) {
    if (m_info == NULL || resp == NULL || resp_max < 2) return 0;
    ensure_valid_fs();
    if (apdu_len < 4) return sw_only(resp, resp_max, SW_WRONG_LENGTH);
    if (apdu[0] != 0x00 && apdu[0] != 0x80) {
        return sw_only(resp, resp_max, SW_CLA_NOT_SUPPORTED);
    }

    cos_apdu_case_t parsed;
    if (!parse_short_apdu(apdu, apdu_len, &parsed)) {
        return sw_only(resp, resp_max, SW_WRONG_LENGTH);
    }

    switch (apdu[1]) {
        case 0xA4:
            return apdu_select(apdu, &parsed, resp, resp_max);
        case 0xB0:
            return apdu_read_binary(apdu, &parsed, resp, resp_max);
        case 0xD6:
            return apdu_update_binary(apdu, &parsed, resp, resp_max);
        case 0xB2:
            return apdu_read_record(apdu, &parsed, resp, resp_max);
        case 0xDC:
            return apdu_update_record(apdu, &parsed, resp, resp_max);
        case 0xE2:
            return apdu_append_record(apdu, &parsed, resp, resp_max);
        case 0x84:
            return apdu_get_challenge(&parsed, resp, resp_max);
        case 0x82:
            m_challenge_len = 0;
            return sw_only(resp, resp_max, SW_SUCCESS);
        default:
            return sw_only(resp, resp_max, SW_INS_NOT_SUPPORTED);
    }
}

uint8_t nfc_cos_create_file(uint16_t parent_fid, uint16_t fid, uint8_t type,
                            uint8_t sfi, uint16_t record_size,
                            const uint8_t *aid, uint8_t aid_len,
                            const uint8_t *data, uint16_t data_len) {
    if (m_info == NULL) return STATUS_INVALID_SLOT_TYPE;
    ensure_valid_fs();
    if (!m_info->write_enabled) return STATUS_CMD_ERR;
    if (fid == 0 || fid == NFC_COS_FID_MF || find_file_by_fid(fid) != NFC_COS_INVALID_IDX) {
        return STATUS_PAR_ERR;
    }
    if (aid_len > NFC_COS_MAX_AID_LEN) return STATUS_PAR_ERR;
    if (sfi > 30) return STATUS_PAR_ERR;
    if (type != NFC_COS_FILE_TYPE_DF &&
            type != NFC_COS_FILE_TYPE_EF_BINARY &&
            type != NFC_COS_FILE_TYPE_EF_RECORD) {
        return STATUS_PAR_ERR;
    }
    if (type == NFC_COS_FILE_TYPE_DF && (sfi != 0 || record_size != 0 || data_len != 0)) {
        return STATUS_PAR_ERR;
    }
    if (type == NFC_COS_FILE_TYPE_EF_BINARY && record_size != 0) {
        return STATUS_PAR_ERR;
    }
    if (type == NFC_COS_FILE_TYPE_EF_RECORD &&
            data_len > 0 && record_size != 0 && data_len != record_size) {
        return STATUS_PAR_ERR;
    }
    if (data_len > 0 && data == NULL) return STATUS_PAR_ERR;
    uint8_t parent_idx = find_file_by_fid(parent_fid);
    if (parent_idx == NFC_COS_INVALID_IDX || !is_df_type(m_info->files[parent_idx].type)) {
        return STATUS_PAR_ERR;
    }

    uint8_t idx = first_free_file();
    if (idx == NFC_COS_INVALID_IDX) return STATUS_MEM_ERR;
    uint16_t storage_len = data_len;
    if (type == NFC_COS_FILE_TYPE_EF_RECORD && data_len > 0) {
        if (data_len > UINT16_MAX - 2) return STATUS_MEM_ERR;
        storage_len = data_len + 2;
    }
    if (is_ef_type(type) && storage_len > NFC_COS_DATA_POOL_SIZE - m_info->pool_used) {
        if (!compact_pool_with_resize(NFC_COS_INVALID_IDX, 0) ||
                storage_len > NFC_COS_DATA_POOL_SIZE - m_info->pool_used) {
            return STATUS_MEM_ERR;
        }
    }

    nfc_cos_file_entry_t *e = &m_info->files[idx];
    memset(e, 0, sizeof(*e));
    e->active = 1;
    e->fid = fid;
    e->parent_fid = parent_fid;
    e->type = type;
    e->sfi = sfi;
    e->record_size = record_size;
    e->aid_len = aid_len;
    if (aid_len > 0 && aid != NULL) memcpy(e->aid, aid, aid_len);
    if (is_ef_type(type) && storage_len > 0) {
        e->data_offset = m_info->pool_used;
        e->data_len = storage_len;
        e->alloc_len = storage_len;
        if (type == NFC_COS_FILE_TYPE_EF_RECORD) {
            put_be16(&m_info->data_pool[e->data_offset], data_len);
            memcpy(&m_info->data_pool[e->data_offset + 2], data, data_len);
        } else {
            memcpy(&m_info->data_pool[e->data_offset], data, data_len);
        }
        m_info->pool_used += storage_len;
    }
    refresh_file_count();
    return STATUS_SUCCESS;
}

uint8_t nfc_cos_delete_file(uint16_t fid) {
    if (m_info == NULL) return STATUS_INVALID_SLOT_TYPE;
    ensure_valid_fs();
    if (!m_info->write_enabled) return STATUS_CMD_ERR;
    return delete_file_recursive(fid);
}

uint8_t nfc_cos_read_file(uint16_t fid, uint16_t offset, uint16_t length,
                          uint8_t *out, uint16_t *out_len, uint16_t out_max) {
    if (m_info == NULL || out == NULL || out_len == NULL) return STATUS_INVALID_SLOT_TYPE;
    ensure_valid_fs();
    uint8_t idx = find_file_by_fid(fid);
    if (idx == NFC_COS_INVALID_IDX || !is_ef_type(m_info->files[idx].type)) {
        return STATUS_PAR_ERR;
    }
    nfc_cos_file_entry_t *e = &m_info->files[idx];
    if (offset > e->data_len) return STATUS_PAR_ERR;
    uint16_t available = e->data_len - offset;
    if (length == 0 || length > available) length = available;
    if (length > out_max) length = out_max;
    memcpy(out, &m_info->data_pool[e->data_offset + offset], length);
    *out_len = length;
    return STATUS_SUCCESS;
}

uint8_t nfc_cos_write_file(uint16_t fid, uint16_t offset,
                           const uint8_t *data, uint16_t data_len) {
    if (m_info == NULL || data == NULL) return STATUS_INVALID_SLOT_TYPE;
    ensure_valid_fs();
    if (!m_info->write_enabled) return STATUS_CMD_ERR;
    uint8_t idx = find_file_by_fid(fid);
    if (idx == NFC_COS_INVALID_IDX || m_info->files[idx].type != NFC_COS_FILE_TYPE_EF_BINARY) {
        return STATUS_PAR_ERR;
    }
    if ((uint32_t)offset + data_len > UINT16_MAX) return STATUS_MEM_ERR;
    uint16_t new_len = offset + data_len;
    if (!ensure_file_capacity(idx, new_len)) return STATUS_MEM_ERR;
    nfc_cos_file_entry_t *e = &m_info->files[idx];
    if (offset > e->data_len) {
        memset(&m_info->data_pool[e->data_offset + e->data_len], 0, offset - e->data_len);
    }
    memcpy(&m_info->data_pool[e->data_offset + offset], data, data_len);
    if (new_len > e->data_len) e->data_len = new_len;
    return STATUS_SUCCESS;
}

uint8_t nfc_cos_append_record(uint16_t fid, const uint8_t *data, uint16_t data_len) {
    if (m_info == NULL || data == NULL) return STATUS_INVALID_SLOT_TYPE;
    ensure_valid_fs();
    if (!m_info->write_enabled) return STATUS_CMD_ERR;
    uint8_t idx = find_file_by_fid(fid);
    if (idx == NFC_COS_INVALID_IDX || m_info->files[idx].type != NFC_COS_FILE_TYPE_EF_RECORD) {
        return STATUS_PAR_ERR;
    }
    if (data_len == 0) return STATUS_PAR_ERR;
    if (data_len > UINT16_MAX - 2) return STATUS_MEM_ERR;
    nfc_cos_file_entry_t *e = &m_info->files[idx];
    if (e->record_size != 0 && data_len != e->record_size) return STATUS_PAR_ERR;
    uint16_t old_len = e->data_len;
    uint16_t new_len = old_len + 2 + data_len;
    if (new_len < old_len || !ensure_file_capacity(idx, new_len)) return STATUS_MEM_ERR;
    put_be16(&m_info->data_pool[e->data_offset + old_len], data_len);
    memcpy(&m_info->data_pool[e->data_offset + old_len + 2], data, data_len);
    e->data_len = new_len;
    return STATUS_SUCCESS;
}

uint16_t nfc_cos_list_files(uint8_t *out, uint16_t out_max) {
    if (m_info == NULL || out == NULL || out_max < 1) return 0;
    ensure_valid_fs();
    uint16_t off = 1;
    uint8_t count = 0;
    for (uint8_t i = 0; i < NFC_COS_MAX_FILES; i++) {
        nfc_cos_file_entry_t *e = &m_info->files[i];
        if (!e->active) continue;
        if (off + NFC_COS_LIST_ENTRY_SIZE > out_max) break;
        out[off++] = i;
        out[off++] = e->type;
        put_be16(&out[off], e->fid);
        off += 2;
        put_be16(&out[off], e->parent_fid);
        off += 2;
        out[off++] = e->sfi;
        put_be16(&out[off], e->type == NFC_COS_FILE_TYPE_EF_RECORD ? record_payload_len(e) : e->data_len);
        off += 2;
        put_be16(&out[off], record_count(e));
        off += 2;
        put_be16(&out[off], e->record_size);
        off += 2;
        out[off++] = e->aid_len;
        memcpy(&out[off], e->aid, NFC_COS_MAX_AID_LEN);
        off += NFC_COS_MAX_AID_LEN;
        count++;
    }
    out[0] = count;
    return off;
}

uint8_t nfc_cos_set_write_enabled(bool enabled) {
    if (m_info == NULL) return STATUS_INVALID_SLOT_TYPE;
    ensure_valid_fs();
    m_info->write_enabled = enabled ? 1 : 0;
    return STATUS_SUCCESS;
}

bool nfc_cos_is_write_enabled(void) {
    return m_info != NULL && m_info->write_enabled != 0;
}

static inline bool is_iblock(uint8_t pcb) {
    return (pcb & PCB_IBLOCK_MASK) == PCB_IBLOCK_VAL;
}

static inline bool is_rblock(uint8_t pcb) {
    return (pcb & 0xC6) == 0x82;
}

static inline bool is_sblock(uint8_t pcb) {
    return (pcb & PCB_IBLOCK_MASK) == PCB_SBLOCK_VAL;
}

static void send_iblock(const uint8_t *data, uint16_t len) {
    uint8_t pcb = 0x02 | (m_block_num & 0x01);
    if (m_cid_supported) pcb |= PCB_CID_FOLLOWING;
    uint8_t off = 0;
    m_tx_buf[off++] = pcb;
    if (m_cid_supported) m_tx_buf[off++] = m_cid & 0x0F;
    if (len > NFC_COS_MAX_APDU) len = NFC_COS_MAX_APDU;
    memcpy(&m_tx_buf[off], data, len);
    nfc_tag_14a_tx_bytes(m_tx_buf, off + len, true);
    m_block_num ^= 1;
}

static void send_rack(void) {
    uint8_t pcb = 0xA2 | (m_block_num & 0x01);
    if (m_cid_supported) {
        pcb |= PCB_CID_FOLLOWING;
        uint8_t buf[2] = { pcb, m_cid & 0x0F };
        nfc_tag_14a_tx_bytes(buf, 2, true);
    } else {
        nfc_tag_14a_tx_bytes(&pcb, 1, true);
    }
}

static void send_wtx(void) {
    uint8_t buf[3];
    uint8_t off = 0;
    buf[off++] = PCB_SBLOCK_WTX | (m_cid_supported ? PCB_CID_FOLLOWING : 0);
    if (m_cid_supported) buf[off++] = m_cid & 0x0F;
    buf[off++] = WTX_VALUE;
    nfc_tag_14a_tx_bytes(buf, off, true);
}

static void nfc_cos_state_handler(uint8_t *data, uint16_t szBits) {
    if (szBits < 8) return;
    uint16_t szBytes = szBits / 8;
    uint8_t pcb = data[0];

    if (is_sblock(pcb)) {
        if ((pcb & 0xF7) == PCB_SBLOCK_DESELECT) {
            nfc_tag_14a_tx_bytes(data, szBytes, true);
            nfc_cos_reset_handler();
            return;
        }
        if ((pcb & 0x3F) == (PCB_SBLOCK_WTX & 0x3F)) {
            uint8_t wtxm = (szBytes > 1) ? data[szBytes - 1] & 0x3F : WTX_VALUE;
            uint8_t resp[3];
            uint8_t off = 0;
            resp[off++] = PCB_SBLOCK_WTX | (m_cid_supported ? PCB_CID_FOLLOWING : 0);
            if (m_cid_supported) resp[off++] = m_cid & 0x0F;
            resp[off++] = wtxm;
            nfc_tag_14a_tx_bytes(resp, off, true);
            return;
        }
        return;
    }

    if (is_rblock(pcb)) {
        send_rack();
        return;
    }

    if (!is_iblock(pcb)) return;

    uint8_t reader_blknum = pcb & PCB_BLOCK_NUM;
    bool has_cid = (pcb & PCB_CID_FOLLOWING) != 0;
    bool has_nad = (pcb & PCB_NAD_FOLLOWING) != 0;
    bool more_chain = (pcb & PCB_CHAIN) != 0;

    uint8_t offset = 1;
    if (has_cid) {
        m_cid_supported = true;
        m_cid = data[offset] & 0x0F;
        offset++;
    }
    if (has_nad) offset++;
    if (offset >= szBytes) {
        send_rack();
        return;
    }

    if (reader_blknum != (m_block_num & 0x01)) {
        send_rack();
        return;
    }

    if (more_chain) {
        send_wtx();
        return;
    }

    uint16_t apdu_len = szBytes - offset;
    if (apdu_len > NFC_COS_MAX_APDU) apdu_len = NFC_COS_MAX_APDU;
    uint16_t resp_len = nfc_cos_process_apdu(&data[offset], apdu_len, m_resp_buf, sizeof(m_resp_buf));
    send_iblock(m_resp_buf, resp_len);
}

nfc_tag_14a_coll_res_reference_t *nfc_cos_get_coll_res(void) {
    if (m_info == NULL) return NULL;
    ensure_valid_fs();
    m_shadow_coll_res.sak = m_info->res_coll.sak;
    m_shadow_coll_res.atqa = m_info->res_coll.atqa;
    m_shadow_coll_res.uid = m_info->res_coll.uid;
    m_shadow_coll_res.size = &m_info->res_coll.size;
    m_shadow_coll_res.ats = &m_info->res_coll.ats;
    return &m_shadow_coll_res;
}

void nfc_cos_reset_handler(void) {
    m_selected_df = 0;
    m_selected_ef = NFC_COS_INVALID_IDX;
    m_challenge_len = 0;
    memset(m_challenge, 0, sizeof(m_challenge));
    m_block_num = 0;
    m_cid_supported = false;
    m_cid = 0;
}

int nfc_cos_data_loadcb(tag_specific_type_t type, tag_data_buffer_t *buffer) {
    UNUSED_PARAMETER(type);
    int info_size = sizeof(nfc_cos_information_t);
    if (buffer->length < info_size) {
        NRF_LOG_ERROR("COS loadcb: buffer too small (%d < %d)", buffer->length, info_size);
        return info_size;
    }
    m_info = (nfc_cos_information_t *)buffer->buffer;
    ensure_valid_fs();
    nfc_cos_reset_handler();

    nfc_tag_14a_handler_t handler = {
        .get_coll_res = nfc_cos_get_coll_res,
        .cb_state = nfc_cos_state_handler,
        .cb_reset = nfc_cos_reset_handler,
    };
    nfc_tag_14a_set_handler(&handler);
    NRF_LOG_INFO("COS loadcb OK: files=%d pool=%d write=%d",
                 m_info->file_count, m_info->pool_used, m_info->write_enabled);
    return info_size;
}

int nfc_cos_data_savecb(tag_specific_type_t type, tag_data_buffer_t *buffer) {
    UNUSED_PARAMETER(type);
    UNUSED_PARAMETER(buffer);
    return sizeof(nfc_cos_information_t);
}

bool nfc_cos_data_factory(uint8_t slot, tag_specific_type_t tag_type) {
    if (tag_type != TAG_TYPE_HF14A_COS) return false;

    nfc_cos_information_t info;
    memset(&info, 0, sizeof(info));
    info.magic = NFC_COS_MAGIC;
    info.version = NFC_COS_VERSION;
    info.write_enabled = 1;
    set_factory_coll_res(&info);
    set_factory_fs(&info);

    fds_slot_record_map_t map_info;
    get_fds_map_by_slot_sense_type_for_dump(slot, TAG_SENSE_HF, &map_info);
    bool ret = fds_write_sync(map_info.id, map_info.key, sizeof(info), &info);
    if (ret && slot == tag_emulation_get_slot()) {
        tag_data_buffer_t *buffer = get_buffer_by_tag_type(tag_type);
        if (buffer != NULL && buffer->length >= sizeof(info)) {
            memcpy(buffer->buffer, &info, sizeof(info));
            nfc_cos_data_loadcb(tag_type, buffer);
        }
    }
    NRF_LOG_INFO("COS factory slot %d: %s", slot, ret ? "OK" : "FAIL");
    return ret;
}
