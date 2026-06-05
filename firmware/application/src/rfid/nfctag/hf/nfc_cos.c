/**
 * @file nfc_cos.c
 * @brief ISO14443-4 CPU-card-like COS emulation.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <stdlib.h>
#include <string.h>
#include <stddef.h>

#include "app_status.h"
#include "crc_utils.h"
#include "fds_util.h"
#include "nfc_cos.h"
#include "sdk_config.h"
#include "tag_persistence.h"
#include "utils.h"

#define NRF_LOG_MODULE_NAME nfc_cos
#include "nrf_log.h"
#include "nrf_log_ctrl.h"
#include "nrf_log_default_backends.h"
NRF_LOG_MODULE_REGISTER();

#define NFC_COS_MAGIC       0x434F5332u /* "COS2" */
#define NFC_COS_VERSION     2u
#define NFC_COS_FID_MF      0x3F00u
#define NFC_COS_INVALID_IDX 0xFFu
#define NFC_COS_FDS_CHUNK_KEY_BASE 0x20u
#define NFC_COS_MAX_CHUNKS  ((NFC_COS_DATA_POOL_SIZE + NFC_COS_FDS_CHUNK_DATA_SIZE - 1) / NFC_COS_FDS_CHUNK_DATA_SIZE)
#define NFC_COS_POOL_ALIGN  4u
#define NFC_COS_FDS_TOTAL_BYTES ((uint32_t)FDS_VIRTUAL_PAGES * (uint32_t)FDS_VIRTUAL_PAGE_SIZE * 4u)
#define NFC_COS_STORAGE_BUDGET_BYTES ((NFC_COS_FDS_TOTAL_BYTES * NFC_COS_STORAGE_PERCENT) / 100u)

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
#define PCB_CID_FOLLOWING   0x08
#define PCB_NAD_FOLLOWING   0x04
#define PCB_CHAIN           0x10
#define PCB_BLOCK_NUM       0x01
#define PCB_SBLOCK_VAL      0xC0
#define PCB_SBLOCK_WTX      0xF2
#define PCB_SBLOCK_DESELECT 0xC2
#define PCB_RBLOCK_NAK      0x10
#define WTX_VALUE           0x3B

#define NFC_COS_TCL_FSC_BYTES 256u
#define NFC_COS_TCL_MAX_INF_NO_CID \
    (NFC_COS_TCL_FSC_BYTES - NFC_TAG_14A_CRC_LENGTH - 1u)

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

typedef struct {
    uint32_t magic;
    uint8_t version;
    uint8_t write_enabled;
    uint8_t file_count;
    uint8_t reserved;
    uint16_t pool_used;
    uint16_t pool_capacity;
    nfc_tag_14a_coll_res_entity_t res_coll;
    nfc_cos_file_entry_t files[NFC_COS_MAX_FILES];
    uint8_t header_padding[2];
} nfc_cos_persisted_header_t;

typedef struct {
    uint8_t idx;
    uint16_t old_offset;
    uint16_t old_alloc_len;
    uint16_t new_offset;
    uint16_t new_alloc_len;
} cos_pool_move_t;

STATIC_ASSERT(sizeof(nfc_cos_persisted_header_t) == offsetof(nfc_cos_information_t, data_pool));
STATIC_ASSERT((sizeof(nfc_cos_persisted_header_t) % 4u) == 0);
STATIC_ASSERT(sizeof(nfc_cos_information_t) <= UINT16_MAX);

static nfc_cos_information_t *m_info = NULL;
static nfc_tag_14a_coll_res_reference_t m_shadow_coll_res;

static uint8_t m_active_slot = 0;
static uint8_t m_selected_df = 0;
static uint8_t m_selected_ef = NFC_COS_INVALID_IDX;
static uint8_t m_challenge[32];
static uint8_t m_challenge_len = 0;

static uint8_t m_block_num = 0;
static bool m_cid_supported = false;
static uint8_t m_cid = 0;
static uint8_t m_apdu_work_buf[NFC_COS_MAX_APDU];
static uint8_t m_resp_buf[NFC_COS_MAX_APDU];
static uint8_t m_tx_buf[NFC_COS_MAX_APDU + 4];
static uint16_t m_resp_len = 0;
static uint16_t m_resp_offset = 0;
static bool m_resp_chaining = false;
static uint16_t m_last_tx_offset = 0;
static uint16_t m_last_tx_len = 0;
static uint8_t m_last_tx_block_num = 0;
static bool m_last_tx_more = false;

static inline uint16_t be16(const uint8_t *p) {
    return ((uint16_t)p[0] << 8) | p[1];
}

static inline void put_be16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static inline void put_be32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static inline uint16_t cos_header_size(void) {
    return sizeof(nfc_cos_persisted_header_t);
}

static inline uint8_t *cos_pool(void) {
    return m_info == NULL ? NULL : m_info->data_pool;
}

static inline uint16_t align_pool_down(uint32_t value) {
    value -= value % NFC_COS_POOL_ALIGN;
    if (value > NFC_COS_DATA_POOL_SIZE) value = NFC_COS_DATA_POOL_SIZE;
    return (uint16_t)value;
}

static uint16_t normalized_pool_capacity(uint16_t capacity) {
    if (capacity < NFC_COS_MIN_DATA_POOL_SIZE) return NFC_COS_MIN_DATA_POOL_SIZE;
    if (capacity > NFC_COS_DATA_POOL_SIZE) return NFC_COS_DATA_POOL_SIZE;
    return align_pool_down(capacity);
}

static uint16_t current_pool_capacity(void) {
    if (m_info == NULL) return NFC_COS_MIN_DATA_POOL_SIZE;
    return normalized_pool_capacity(m_info->pool_capacity);
}

static uint32_t cos_min_slot_occupancy(void) {
    return (uint32_t)cos_header_size() + NFC_COS_MIN_DATA_POOL_SIZE;
}

static uint32_t cos_slot_occupancy_from_capacity(uint16_t capacity) {
    return (uint32_t)cos_header_size() + normalized_pool_capacity(capacity);
}

static uint16_t cos_chunk_key(uint8_t chunk_idx) {
    return (uint16_t)(NFC_COS_FDS_CHUNK_KEY_BASE + chunk_idx);
}

static bool cos_header_is_valid(const nfc_cos_persisted_header_t *header) {
    return header != NULL &&
           header->magic == NFC_COS_MAGIC &&
           header->version == NFC_COS_VERSION &&
           header->files[0].active &&
           header->files[0].fid == NFC_COS_FID_MF &&
           header->pool_capacity >= NFC_COS_MIN_DATA_POOL_SIZE &&
           header->pool_capacity <= NFC_COS_DATA_POOL_SIZE &&
           header->pool_used <= header->pool_capacity;
}

static bool cos_read_slot_header(uint8_t slot, nfc_cos_persisted_header_t *header) {
    if (header == NULL || slot >= TAG_MAX_SLOT_NUM) return false;
    fds_slot_record_map_t map_info;
    get_fds_map_by_slot_sense_type_for_dump(slot, TAG_SENSE_HF, &map_info);
    uint16_t length = sizeof(*header);
    memset(header, 0, sizeof(*header));
    if (!fds_read_sync(map_info.id, map_info.key, &length, (uint8_t *)header)) {
        return false;
    }
    return length >= sizeof(*header) && cos_header_is_valid(header);
}

static uint16_t cos_calculate_slot_pool_capacity(uint8_t slot, uint32_t *other_occupancy) {
    uint32_t used_other = 0;
    for (uint8_t i = 0; i < TAG_MAX_SLOT_NUM; i++) {
        if (i == slot) continue;
        nfc_cos_persisted_header_t header;
        if (cos_read_slot_header(i, &header)) {
            used_other += cos_slot_occupancy_from_capacity(header.pool_capacity);
        } else {
            used_other += cos_min_slot_occupancy();
        }
    }

    if (other_occupancy != NULL) *other_occupancy = used_other;

    uint32_t min_self = cos_min_slot_occupancy();
    if (NFC_COS_STORAGE_BUDGET_BYTES <= used_other + min_self) {
        return NFC_COS_MIN_DATA_POOL_SIZE;
    }

    uint32_t available_pool = NFC_COS_STORAGE_BUDGET_BYTES - used_other - cos_header_size();
    if (available_pool < NFC_COS_MIN_DATA_POOL_SIZE) return NFC_COS_MIN_DATA_POOL_SIZE;
    return align_pool_down(available_pool);
}

static void cos_refresh_dynamic_capacity(void) {
    if (m_info == NULL) return;
    uint16_t calculated = cos_calculate_slot_pool_capacity(m_active_slot, NULL);
    uint16_t min_needed = normalized_pool_capacity(m_info->pool_used);
    if (calculated < min_needed) calculated = min_needed;
    m_info->pool_capacity = normalized_pool_capacity(calculated);
}

static bool cos_read_pool_chunks(void) {
    if (m_info == NULL || m_info->pool_used > current_pool_capacity()) return false;
    uint8_t *pool = cos_pool();
    uint16_t capacity = current_pool_capacity();
    memset(pool, 0, capacity);

    fds_slot_record_map_t map_info;
    get_fds_map_by_slot_sense_type_for_dump(m_active_slot, TAG_SENSE_HF, &map_info);

    uint16_t remaining = m_info->pool_used;
    uint16_t offset = 0;
    for (uint8_t i = 0; i < NFC_COS_MAX_CHUNKS && remaining > 0; i++) {
        uint16_t chunk_len = remaining > NFC_COS_FDS_CHUNK_DATA_SIZE ?
                             NFC_COS_FDS_CHUNK_DATA_SIZE : remaining;
        uint16_t stored_len = (uint16_t)((chunk_len + 3u) & ~3u);
        if (!fds_read_sync(map_info.id, cos_chunk_key(i), &stored_len, &pool[offset]) ||
                stored_len < chunk_len) {
            NRF_LOG_ERROR("COS slot %d chunk %d missing (%d/%d)",
                          m_active_slot, i, stored_len, chunk_len);
            return false;
        }
        offset += chunk_len;
        remaining -= chunk_len;
    }
    return remaining == 0;
}

static bool cos_write_pool_chunks(void) {
    if (m_info == NULL || m_info->pool_used > current_pool_capacity()) return false;
    uint8_t *pool = cos_pool();
    fds_slot_record_map_t map_info;
    get_fds_map_by_slot_sense_type_for_dump(m_active_slot, TAG_SENSE_HF, &map_info);

    uint16_t remaining = m_info->pool_used;
    uint16_t offset = 0;
    for (uint8_t i = 0; i < NFC_COS_MAX_CHUNKS; i++) {
        uint16_t key = cos_chunk_key(i);
        if (remaining > 0) {
            uint16_t chunk_len = remaining > NFC_COS_FDS_CHUNK_DATA_SIZE ?
                                 NFC_COS_FDS_CHUNK_DATA_SIZE : remaining;
            fds_delete_sync(map_info.id, key);
            if (!fds_write_sync(map_info.id, key, chunk_len, &pool[offset])) {
                NRF_LOG_ERROR("COS slot %d chunk %d write failed", m_active_slot, i);
                return false;
            }
            offset += chunk_len;
            remaining -= chunk_len;
        } else {
            fds_delete_sync(map_info.id, key);
        }
    }
    return true;
}

void nfc_cos_storage_delete(uint8_t slot) {
    if (slot >= TAG_MAX_SLOT_NUM) return;
    fds_slot_record_map_t map_info;
    get_fds_map_by_slot_sense_type_for_dump(slot, TAG_SENSE_HF, &map_info);
    for (uint8_t i = 0; i < NFC_COS_MAX_CHUNKS; i++) {
        fds_delete_sync(map_info.id, cos_chunk_key(i));
    }
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

static const uint8_t *stage_apdu_data(const cos_apdu_case_t *parsed) {
    if (parsed == NULL || !parsed->has_lc || parsed->data == NULL) return NULL;
    if ((uint16_t)parsed->lc > sizeof(m_apdu_work_buf)) return NULL;
    memcpy(m_apdu_work_buf, parsed->data, parsed->lc);
    return m_apdu_work_buf;
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
    for (uint8_t i = 0; i < NFC_COS_MAX_FILES; i++) {
        nfc_cos_file_entry_t *e = &m_info->files[i];
        if (!e->active || e->parent_fid != parent_fid || e->fid != sfi) continue;
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
    uint8_t *pool = cos_pool();
    uint16_t off = 0;
    uint16_t count = 0;
    while (off + 2 <= e->data_len) {
        uint16_t len = be16(&pool[e->data_offset + off]);
        if (off + 2 + len > e->data_len) break;
        off += 2 + len;
        count++;
    }
    return count;
}

static uint16_t record_payload_len(const nfc_cos_file_entry_t *e) {
    if (e->type != NFC_COS_FILE_TYPE_EF_RECORD || e->data_len == 0) return 0;
    uint8_t *pool = cos_pool();
    uint16_t off = 0;
    uint16_t total = 0;
    while (off + 2 <= e->data_len) {
        uint16_t len = be16(&pool[e->data_offset + off]);
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
    uint8_t *pool = cos_pool();
    while (off + 2 <= e->data_len) {
        uint16_t len = be16(&pool[e->data_offset + off]);
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
    uint8_t *pool = cos_pool();
    uint16_t old_pool_used = m_info->pool_used;
    uint16_t used = 0;
    bool move_upward = false;
    uint8_t move_count = 0;
    cos_pool_move_t moves[NFC_COS_MAX_FILES];

    for (uint8_t i = 0; i < NFC_COS_MAX_FILES; i++) {
        nfc_cos_file_entry_t *e = &m_info->files[i];
        if (!e->active || !is_ef_type(e->type)) continue;
        uint8_t pos = move_count++;
        moves[pos].idx = i;
        moves[pos].old_offset = e->data_offset;
        moves[pos].old_alloc_len = e->alloc_len;
    }

    for (uint8_t i = 1; i < move_count; i++) {
        cos_pool_move_t item = moves[i];
        int j = (int)i - 1;
        while (j >= 0 && moves[j].old_offset > item.old_offset) {
            moves[j + 1] = moves[j];
            j--;
        }
        moves[j + 1] = item;
    }

    for (uint8_t i = 0; i < move_count; i++) {
        nfc_cos_file_entry_t *e = &m_info->files[moves[i].idx];
        uint16_t alloc_len = (moves[i].idx == resize_idx) ? new_alloc_len : e->alloc_len;
        if ((uint32_t)used + alloc_len > current_pool_capacity()) return false;
        moves[i].new_offset = used;
        moves[i].new_alloc_len = alloc_len;
        if (alloc_len != 0 && used > moves[i].old_offset) move_upward = true;
        used += alloc_len;
    }

    if (move_upward) {
        for (int i = (int)move_count - 1; i >= 0; i--) {
            nfc_cos_file_entry_t *e = &m_info->files[moves[i].idx];
            uint16_t copy_len = e->data_len;
            if (copy_len > moves[i].new_alloc_len) copy_len = moves[i].new_alloc_len;
            if (copy_len > 0 && moves[i].old_alloc_len > 0) {
                memmove(&pool[moves[i].new_offset], &pool[moves[i].old_offset], copy_len);
            }
            e->data_offset = moves[i].new_alloc_len == 0 ? 0 : moves[i].new_offset;
            e->alloc_len = moves[i].new_alloc_len;
            if (e->data_len > e->alloc_len) e->data_len = e->alloc_len;
        }
    } else {
        for (uint8_t i = 0; i < move_count; i++) {
            nfc_cos_file_entry_t *e = &m_info->files[moves[i].idx];
            uint16_t copy_len = e->data_len;
            if (copy_len > moves[i].new_alloc_len) copy_len = moves[i].new_alloc_len;
            if (copy_len > 0 && moves[i].old_alloc_len > 0) {
                memmove(&pool[moves[i].new_offset], &pool[moves[i].old_offset], copy_len);
            }
            e->data_offset = moves[i].new_alloc_len == 0 ? 0 : moves[i].new_offset;
            e->alloc_len = moves[i].new_alloc_len;
            if (e->data_len > e->alloc_len) e->data_len = e->alloc_len;
        }
    }

    if (used < old_pool_used) {
        memset(&pool[used], 0, old_pool_used - used);
    }
    m_info->pool_used = used;
    return true;
}

static bool ensure_file_capacity(uint8_t idx, uint16_t len) {
    nfc_cos_file_entry_t *e = &m_info->files[idx];
    if (len <= e->alloc_len) return true;

    if (e->alloc_len == 0) {
        uint32_t new_end = (uint32_t)m_info->pool_used + len;
        if (new_end <= current_pool_capacity()) {
            e->data_offset = m_info->pool_used;
            e->alloc_len = len;
            m_info->pool_used = (uint16_t)new_end;
            return true;
        }
    } else {
        uint32_t old_end = (uint32_t)e->data_offset + e->alloc_len;
        uint32_t new_end = (uint32_t)e->data_offset + len;
        if (old_end == m_info->pool_used && new_end <= current_pool_capacity()) {
            e->alloc_len = len;
            m_info->pool_used = (uint16_t)new_end;
            return true;
        }
    }

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

static void set_factory_coll_res_entity(nfc_tag_14a_coll_res_entity_t *res_coll) {
    res_coll->size = NFC_TAG_14A_UID_DOUBLE_SIZE;
    res_coll->atqa[0] = 0x04;
    res_coll->atqa[1] = 0x00;
    res_coll->sak[0] = 0x20;
    res_coll->uid[0] = 0x04;
    res_coll->uid[1] = 0xC0;
    res_coll->uid[2] = 0x5E;
    res_coll->uid[3] = 0x00;
    res_coll->uid[4] = 0x00;
    res_coll->uid[5] = 0x00;
    res_coll->uid[6] = 0x01;

    static const uint8_t default_ats[] = {
        0x10, 0x78, 0x80, 0x70, 0x02, 0x00,
        0x31, 0xC1, 0x64, 0x09, 0x97, 0x61,
        0x26, 0x00, 0x90, 0x00
    };
    res_coll->ats.length = sizeof(default_ats);
    memcpy(res_coll->ats.data, default_ats, sizeof(default_ats));
}

static void set_factory_header(nfc_cos_persisted_header_t *header, uint16_t pool_capacity) {
    memset(header, 0, sizeof(*header));
    header->magic = NFC_COS_MAGIC;
    header->version = NFC_COS_VERSION;
    header->write_enabled = 1;
    header->pool_capacity = normalized_pool_capacity(pool_capacity);
    header->pool_used = 0;
    header->file_count = 1;
    set_factory_coll_res_entity(&header->res_coll);

    nfc_cos_file_entry_t *mf = &header->files[0];
    mf->active = 1;
    mf->fid = NFC_COS_FID_MF;
    mf->parent_fid = 0x0000;
    mf->type = NFC_COS_FILE_TYPE_MF;
}

static void set_factory_fs(nfc_cos_information_t *info, uint16_t pool_capacity) {
    set_factory_header((nfc_cos_persisted_header_t *)info, pool_capacity);
    memset(info->data_pool, 0, current_pool_capacity());
}

static void ensure_valid_fs(void) {
    if (m_info == NULL) return;
    if (m_info->magic == NFC_COS_MAGIC && m_info->version == NFC_COS_VERSION &&
            m_info->files[0].active && m_info->files[0].fid == NFC_COS_FID_MF &&
            m_info->pool_capacity >= NFC_COS_MIN_DATA_POOL_SIZE &&
            m_info->pool_capacity <= NFC_COS_DATA_POOL_SIZE &&
            m_info->pool_used <= m_info->pool_capacity) {
        m_info->pool_capacity = normalized_pool_capacity(m_info->pool_capacity);
        cos_refresh_dynamic_capacity();
        return;
    }

    memset(m_info, 0, sizeof(*m_info));
    set_factory_fs(m_info, cos_calculate_slot_pool_capacity(m_active_slot, NULL));
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

static uint16_t build_df_fci(uint8_t idx, uint8_t *resp, uint16_t resp_max) {
    if (resp_max < 2) return 0;
    nfc_cos_file_entry_t *e = &m_info->files[idx];
    if (e->type != NFC_COS_FILE_TYPE_DF || e->aid_len == 0) {
        return sw_only(resp, resp_max, SW_SUCCESS);
    }

    uint16_t body_len = 2u + e->aid_len + 14u;
    if ((uint32_t)body_len + 4u > resp_max || body_len > 0xFFu) {
        return sw_only(resp, resp_max, SW_WRONG_LENGTH);
    }

    uint16_t off = 0;
    resp[off++] = 0x6F;
    resp[off++] = (uint8_t)body_len;
    resp[off++] = 0x84;
    resp[off++] = e->aid_len;
    memcpy(&resp[off], e->aid, e->aid_len);
    off += e->aid_len;
    resp[off++] = 0xA5;
    resp[off++] = 0x0C;
    resp[off++] = 0x9F;
    resp[off++] = 0x08;
    resp[off++] = 0x01;
    resp[off++] = 0x02;
    resp[off++] = 0x9F;
    resp[off++] = 0x0C;
    resp[off++] = 0x05;
    memset(&resp[off], 0, 5);
    off += 5;
    return append_sw(resp, off, resp_max, SW_SUCCESS);
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
    return build_df_fci(idx, resp, resp_max);
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
    uint8_t *base = &cos_pool()[e->data_offset];
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

static uint8_t append_record_by_index(uint8_t idx, const uint8_t *data, uint16_t data_len) {
    if (data == NULL || data_len == 0) return STATUS_PAR_ERR;
    if (data_len > UINT16_MAX - 2) return STATUS_MEM_ERR;
    nfc_cos_file_entry_t *e = &m_info->files[idx];
    if (e->type != NFC_COS_FILE_TYPE_EF_RECORD) return STATUS_PAR_ERR;
    if (e->record_size != 0 && data_len != e->record_size) return STATUS_PAR_ERR;

    uint16_t old_len = e->data_len;
    uint16_t new_len = old_len + 2 + data_len;
    if (new_len < old_len || !ensure_file_capacity(idx, new_len)) return STATUS_MEM_ERR;
    e = &m_info->files[idx];
    put_be16(&cos_pool()[e->data_offset + old_len], data_len);
    memcpy(&cos_pool()[e->data_offset + old_len + 2], data, data_len);
    e->data_len = new_len;
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
    if (out_len > 0) memcpy(resp, &cos_pool()[e->data_offset + offset], out_len);
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
    const uint8_t *write_data = stage_apdu_data(parsed);
    if (write_data == NULL) return sw_only(resp, resp_max, SW_WRONG_LENGTH);

    uint16_t new_len = offset + parsed->lc;
    if (!ensure_file_capacity(idx, new_len)) {
        return sw_only(resp, resp_max, SW_NOT_ENOUGH_MEMORY);
    }
    e = &m_info->files[idx];
    if (offset > e->data_len) {
        memset(&cos_pool()[e->data_offset + e->data_len], 0, offset - e->data_len);
    }
    memcpy(&cos_pool()[e->data_offset + offset], write_data, parsed->lc);
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
                                  &cos_pool()[e->data_offset + off + 2],
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

    const uint8_t *write_data = stage_apdu_data(parsed);
    if (write_data == NULL) return sw_only(resp, resp_max, SW_WRONG_LENGTH);

    uint8_t st = append_record_by_index(idx, write_data, parsed->lc);
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
    const uint8_t *write_data = stage_apdu_data(parsed);
    if (write_data == NULL) return sw_only(resp, resp_max, SW_WRONG_LENGTH);

    uint8_t st = update_record_by_index(idx, apdu[2], write_data, parsed->lc, &record_not_found);
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
    if (fid == 0 || fid == NFC_COS_FID_MF ||
            find_child_by_fid(parent_fid, fid, 0) != NFC_COS_INVALID_IDX) {
        return STATUS_PAR_ERR;
    }

    uint8_t idx = first_free_file();
    if (idx == NFC_COS_INVALID_IDX) return STATUS_MEM_ERR;
    uint16_t storage_len = data_len;
    if (type == NFC_COS_FILE_TYPE_EF_RECORD && data_len > 0) {
        if (data_len > UINT16_MAX - 2) return STATUS_MEM_ERR;
        storage_len = data_len + 2;
    }
    if (is_ef_type(type) && storage_len > current_pool_capacity() - m_info->pool_used) {
        if (!compact_pool_with_resize(NFC_COS_INVALID_IDX, 0) ||
                storage_len > current_pool_capacity() - m_info->pool_used) {
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
            put_be16(&cos_pool()[e->data_offset], data_len);
            memcpy(&cos_pool()[e->data_offset + 2], data, data_len);
        } else {
            memcpy(&cos_pool()[e->data_offset], data, data_len);
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
    memcpy(out, &cos_pool()[e->data_offset + offset], length);
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
        memset(&cos_pool()[e->data_offset + e->data_len], 0, offset - e->data_len);
    }
    memcpy(&cos_pool()[e->data_offset + offset], data, data_len);
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
    return append_record_by_index(idx, data, data_len);
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

uint16_t nfc_cos_storage_info(uint8_t *out, uint16_t out_max) {
    if (m_info == NULL || out == NULL || out_max < NFC_COS_STORAGE_INFO_SIZE) return 0;
    ensure_valid_fs();
    uint32_t other_occupancy = 0;
    uint16_t calculated = cos_calculate_slot_pool_capacity(m_active_slot, &other_occupancy);
    uint16_t capacity = current_pool_capacity();
    uint32_t slot_occupancy = cos_slot_occupancy_from_capacity(capacity);

    put_be32(&out[0], NFC_COS_FDS_TOTAL_BYTES);
    put_be32(&out[4], NFC_COS_STORAGE_BUDGET_BYTES);
    put_be32(&out[8], other_occupancy);
    put_be32(&out[12], slot_occupancy);
    put_be16(&out[16], cos_header_size());
    put_be16(&out[18], NFC_COS_MIN_DATA_POOL_SIZE);
    put_be16(&out[20], NFC_COS_DATA_POOL_SIZE);
    put_be16(&out[22], capacity);
    put_be16(&out[24], m_info->pool_used);
    put_be16(&out[26], NFC_COS_FDS_CHUNK_DATA_SIZE);
    put_be16(&out[28], NFC_COS_MAX_CHUNKS);
    put_be16(&out[30], calculated);
    out[32] = m_info->file_count;
    out[33] = m_active_slot;
    return NFC_COS_STORAGE_INFO_SIZE;
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

static uint16_t max_inf_per_block(void) {
    uint16_t max_len = NFC_COS_TCL_MAX_INF_NO_CID;
    if (m_cid_supported && max_len > 0) max_len--;
    return max_len;
}

static void send_iblock_frame(const uint8_t *data, uint16_t len,
                              bool more, uint8_t block_num, bool advance_block) {
    uint8_t pcb = 0x02 | (block_num & 0x01);
    if (more) pcb |= PCB_CHAIN;
    if (m_cid_supported) pcb |= PCB_CID_FOLLOWING;
    uint8_t off = 0;
    m_tx_buf[off++] = pcb;
    if (m_cid_supported) m_tx_buf[off++] = m_cid & 0x0F;
    if (len > max_inf_per_block()) len = max_inf_per_block();
    memcpy(&m_tx_buf[off], data, len);
    nfc_tag_14a_tx_bytes(m_tx_buf, off + len, true);
    if (advance_block) m_block_num ^= 1;
}

static void send_response_chunk(bool retransmit) {
    if (retransmit && m_last_tx_len > 0) {
        send_iblock_frame(&m_resp_buf[m_last_tx_offset], m_last_tx_len,
                          m_last_tx_more, m_last_tx_block_num, false);
        return;
    }

    if (m_resp_offset >= m_resp_len) {
        m_resp_chaining = false;
        return;
    }

    uint16_t chunk_len = m_resp_len - m_resp_offset;
    uint16_t max_len = max_inf_per_block();
    if (chunk_len > max_len) chunk_len = max_len;
    bool more = (m_resp_offset + chunk_len) < m_resp_len;

    m_last_tx_offset = m_resp_offset;
    m_last_tx_len = chunk_len;
    m_last_tx_block_num = m_block_num & 0x01;
    m_last_tx_more = more;

    send_iblock_frame(&m_resp_buf[m_resp_offset], chunk_len, more, m_block_num, true);
    m_resp_offset += chunk_len;
    m_resp_chaining = more;
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

static void clamp_rf_response_to_single_frame(void) {
    uint16_t max_len = max_inf_per_block();
    if (m_resp_len <= max_len || max_len < 2) return;

    /* Some readers do not continue ISO-DEP response chaining; keep SW visible. */
    uint8_t sw1 = m_resp_buf[m_resp_len - 2];
    uint8_t sw2 = m_resp_buf[m_resp_len - 1];
    m_resp_buf[max_len - 2] = sw1;
    m_resp_buf[max_len - 1] = sw2;
    m_resp_len = max_len;
}

static void nfc_cos_state_handler(uint8_t *data, uint16_t szBits) {
    if (szBits < ((1 + NFC_TAG_14A_CRC_LENGTH) * 8) || (szBits & 0x07) != 0) return;

    uint16_t szBytes = szBits / 8;
    if (!nfc_tag_14a_checks_crc(data, szBytes)) return;
    szBytes -= NFC_TAG_14A_CRC_LENGTH;

    uint8_t pcb = data[0];

    if (is_sblock(pcb)) {
        if ((pcb & (uint8_t)~PCB_CID_FOLLOWING) == PCB_SBLOCK_DESELECT) {
            nfc_tag_14a_tx_bytes(data, szBytes, true);
            nfc_cos_reset_handler();
            return;
        }
        if ((pcb & (uint8_t)~PCB_CID_FOLLOWING) == PCB_SBLOCK_WTX) {
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
        bool nak = (pcb & PCB_RBLOCK_NAK) != 0;
        if (nak) {
            send_response_chunk(true);
        } else if (m_resp_chaining) {
            send_response_chunk(false);
        } else {
            send_rack();
        }
        return;
    }

    if (!is_iblock(pcb)) return;

    uint8_t reader_blknum = pcb & PCB_BLOCK_NUM;
    bool has_cid = (pcb & PCB_CID_FOLLOWING) != 0;
    bool has_nad = (pcb & PCB_NAD_FOLLOWING) != 0;
    bool more_chain = (pcb & PCB_CHAIN) != 0;

    uint8_t offset = 1;
    if (has_cid) {
        if (offset >= szBytes) {
            send_rack();
            return;
        }
        m_cid_supported = true;
        m_cid = data[offset] & 0x0F;
        offset++;
    } else {
        m_cid_supported = false;
    }
    if (has_nad) {
        if (offset >= szBytes) {
            send_rack();
            return;
        }
        offset++;
    }
    if (offset >= szBytes) {
        send_rack();
        return;
    }

    if (reader_blknum != (m_block_num & 0x01)) {
        send_response_chunk(true);
        return;
    }

    if (more_chain) {
        send_wtx();
        return;
    }

    uint16_t apdu_len = szBytes - offset;
    if (apdu_len > NFC_COS_MAX_APDU) apdu_len = NFC_COS_MAX_APDU;
    m_resp_len = nfc_cos_process_apdu(&data[offset], apdu_len, m_resp_buf, sizeof(m_resp_buf));
    clamp_rf_response_to_single_frame();
    m_resp_offset = 0;
    m_resp_chaining = false;
    m_last_tx_len = 0;
    send_response_chunk(false);
}

nfc_tag_14a_coll_res_reference_t *nfc_cos_get_coll_res(void) {
    if (m_info == NULL) return NULL;
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
    m_resp_len = 0;
    m_resp_offset = 0;
    m_resp_chaining = false;
    m_last_tx_len = 0;
}

int nfc_cos_data_loadcb(tag_specific_type_t type, tag_data_buffer_t *buffer) {
    UNUSED_PARAMETER(type);
    int info_size = sizeof(nfc_cos_information_t);
    if (buffer->length < info_size) {
        NRF_LOG_ERROR("COS loadcb: buffer too small (%d < %d)", buffer->length, info_size);
        return info_size;
    }
    m_active_slot = tag_emulation_get_slot();
    m_info = (nfc_cos_information_t *)buffer->buffer;
    ensure_valid_fs();
    if (!cos_read_pool_chunks()) {
        NRF_LOG_WARNING("COS slot %d pool chunks invalid, resetting filesystem", m_active_slot);
        set_factory_fs(m_info, cos_calculate_slot_pool_capacity(m_active_slot, NULL));
        nfc_cos_storage_delete(m_active_slot);
    }
    nfc_cos_reset_handler();

    nfc_tag_14a_handler_t handler = {
        .get_coll_res = nfc_cos_get_coll_res,
        .cb_state = nfc_cos_state_handler,
        .cb_reset = nfc_cos_reset_handler,
    };
    nfc_tag_14a_set_handler(&handler);
    nfc_tag_14a_set_reset_enable(true);
    NRF_LOG_INFO("COS loadcb OK: files=%d pool=%d/%d write=%d",
                 m_info->file_count, m_info->pool_used, m_info->pool_capacity, m_info->write_enabled);
    return cos_header_size();
}

int nfc_cos_data_savecb(tag_specific_type_t type, tag_data_buffer_t *buffer) {
    UNUSED_PARAMETER(type);
    if (buffer == NULL || buffer->buffer == NULL || buffer->length < sizeof(nfc_cos_information_t)) {
        return 0;
    }
    m_info = (nfc_cos_information_t *)buffer->buffer;
    m_active_slot = tag_emulation_get_slot();
    ensure_valid_fs();
    if (!cos_write_pool_chunks()) {
        return 0;
    }

    fds_slot_record_map_t map_info;
    get_fds_map_by_slot_sense_type_for_dump(m_active_slot, TAG_SENSE_HF, &map_info);
    fds_delete_sync(map_info.id, map_info.key);
    if (!fds_write_sync(map_info.id, map_info.key, cos_header_size(), buffer->buffer)) {
        NRF_LOG_ERROR("COS slot %d header write failed", m_active_slot);
        return 0;
    }
    if (buffer->crc != NULL) {
        calc_14a_crc_lut(buffer->buffer, cos_header_size(), (uint8_t *)buffer->crc);
    }
    return 0;
}

bool nfc_cos_data_factory(uint8_t slot, tag_specific_type_t tag_type) {
    if (tag_type != TAG_TYPE_HF14A_COS) return false;

    nfc_cos_persisted_header_t header;
    set_factory_header(&header, cos_calculate_slot_pool_capacity(slot, NULL));
    nfc_cos_storage_delete(slot);

    fds_slot_record_map_t map_info;
    get_fds_map_by_slot_sense_type_for_dump(slot, TAG_SENSE_HF, &map_info);
    fds_delete_sync(map_info.id, map_info.key);
    bool ret = fds_write_sync(map_info.id, map_info.key, sizeof(header), &header);
    if (ret && slot == tag_emulation_get_slot()) {
        tag_data_buffer_t *buffer = get_buffer_by_tag_type(tag_type);
        if (buffer != NULL && buffer->length >= sizeof(nfc_cos_information_t)) {
            memset(buffer->buffer, 0, buffer->length);
            memcpy(buffer->buffer, &header, sizeof(header));
            nfc_cos_data_loadcb(tag_type, buffer);
        }
    }
    NRF_LOG_INFO("COS factory slot %d: %s", slot, ret ? "OK" : "FAIL");
    return ret;
}
