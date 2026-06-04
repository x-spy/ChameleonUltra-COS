/**
 * @file nfc_cos.h
 * @brief ISO14443-4 CPU-card-like COS emulation.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef NFC_COS_H
#define NFC_COS_H

#include <stdbool.h>
#include <stdint.h>

#include "nfc_14a.h"
#include "tag_emulation.h"

#define NFC_COS_MAX_APDU              260
#define NFC_COS_MAX_FILES             32
#define NFC_COS_MAX_AID_LEN           16
#define NFC_COS_MIN_DATA_POOL_SIZE    3200
#define NFC_COS_DATA_POOL_SIZE        64000
#define NFC_COS_FDS_CHUNK_DATA_SIZE   7600
#define NFC_COS_STORAGE_PERCENT       90
#define NFC_COS_LIST_ENTRY_SIZE       30
#define NFC_COS_LIST_MAX_LEN          (1 + (NFC_COS_MAX_FILES * NFC_COS_LIST_ENTRY_SIZE))
#define NFC_COS_STORAGE_INFO_SIZE     34

typedef enum {
    NFC_COS_FILE_TYPE_MF        = 0x01,
    NFC_COS_FILE_TYPE_DF        = 0x02,
    NFC_COS_FILE_TYPE_EF_BINARY = 0x04,
    NFC_COS_FILE_TYPE_EF_RECORD = 0x05,
} nfc_cos_file_type_t;

typedef struct __attribute__((packed)) {
    uint16_t fid;
    uint16_t parent_fid;
    uint8_t type;
    uint8_t sfi;
    uint16_t record_size;
    uint16_t data_offset;
    uint16_t data_len;
    uint16_t alloc_len;
    uint8_t aid_len;
    uint8_t aid[NFC_COS_MAX_AID_LEN];
    uint8_t active;
} nfc_cos_file_entry_t;

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
    uint8_t data_pool[NFC_COS_DATA_POOL_SIZE];
} nfc_cos_information_t;

nfc_tag_14a_coll_res_reference_t *nfc_cos_get_coll_res(void);

int nfc_cos_data_loadcb(tag_specific_type_t type, tag_data_buffer_t *buffer);
int nfc_cos_data_savecb(tag_specific_type_t type, tag_data_buffer_t *buffer);
bool nfc_cos_data_factory(uint8_t slot, tag_specific_type_t tag_type);

void nfc_cos_reset_handler(void);

uint16_t nfc_cos_process_apdu(const uint8_t *apdu, uint16_t apdu_len,
                              uint8_t *resp, uint16_t resp_max);

uint8_t nfc_cos_create_file(uint16_t parent_fid, uint16_t fid, uint8_t type,
                            uint8_t sfi, uint16_t record_size,
                            const uint8_t *aid, uint8_t aid_len,
                            const uint8_t *data, uint16_t data_len);
uint8_t nfc_cos_delete_file(uint16_t fid);
uint8_t nfc_cos_read_file(uint16_t fid, uint16_t offset, uint16_t length,
                          uint8_t *out, uint16_t *out_len, uint16_t out_max);
uint8_t nfc_cos_write_file(uint16_t fid, uint16_t offset,
                           const uint8_t *data, uint16_t data_len);
uint8_t nfc_cos_append_record(uint16_t fid, const uint8_t *data, uint16_t data_len);
uint16_t nfc_cos_list_files(uint8_t *out, uint16_t out_max);
uint16_t nfc_cos_storage_info(uint8_t *out, uint16_t out_max);
void nfc_cos_storage_delete(uint8_t slot);
uint8_t nfc_cos_set_write_enabled(bool enabled);
bool nfc_cos_is_write_enabled(void);

#endif /* NFC_COS_H */
