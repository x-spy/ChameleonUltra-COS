#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "app_status.h"
#include "nfc_cos.h"

static tag_data_buffer_t *g_active_buffer;

tag_data_buffer_t *get_buffer_by_tag_type(tag_specific_type_t type) {
    (void)type;
    return g_active_buffer;
}

uint8_t tag_emulation_get_slot(void) {
    return 0;
}

void nfc_tag_14a_set_handler(nfc_tag_14a_handler_t *handler) {
    (void)handler;
}

void nfc_tag_14a_tx_bytes(uint8_t *data, uint32_t bytes, bool appendCrc) {
    (void)data;
    (void)bytes;
    (void)appendCrc;
}

void nfc_tag_14a_set_reset_enable(bool enable) {
    (void)enable;
}

bool is_valid_uid_size(uint8_t uid_length) {
    return uid_length == NFC_TAG_14A_UID_SINGLE_SIZE ||
           uid_length == NFC_TAG_14A_UID_DOUBLE_SIZE ||
           uid_length == NFC_TAG_14A_UID_TRIPLE_SIZE;
}

bool nfc_tag_14a_checks_crc(uint8_t *pbtData, size_t szLen) {
    (void)pbtData;
    (void)szLen;
    return true;
}

static void expect_hex(const uint8_t *got, uint16_t got_len, const uint8_t *want, uint16_t want_len) {
    if (got_len != want_len || memcmp(got, want, want_len) != 0) {
        fprintf(stderr, "response mismatch\n got:");
        for (uint16_t i = 0; i < got_len; i++) fprintf(stderr, " %02X", got[i]);
        fprintf(stderr, "\nwant:");
        for (uint16_t i = 0; i < want_len; i++) fprintf(stderr, " %02X", want[i]);
        fprintf(stderr, "\n");
        abort();
    }
}

int main(void) {
    static nfc_cos_information_t info;
    uint16_t crc = 0;
    tag_data_buffer_t buffer = {
        .length = sizeof(info),
        .buffer = (uint8_t *)&info,
        .crc = &crc,
    };
    uint8_t resp[NFC_COS_MAX_APDU];
    g_active_buffer = &buffer;

    srand(1);
    assert(nfc_cos_data_loadcb(TAG_TYPE_HF14A_COS, &buffer) > 0);
    assert(nfc_cos_is_write_enabled());

    uint8_t storage[NFC_COS_STORAGE_INFO_SIZE];
    assert(nfc_cos_storage_info(storage, sizeof(storage)) == NFC_COS_STORAGE_INFO_SIZE);
    uint16_t pool_capacity = ((uint16_t)storage[22] << 8) | storage[23];
    assert(pool_capacity >= NFC_COS_MIN_DATA_POOL_SIZE);

    const uint8_t bin_data[] = {0x10, 0x11, 0x12, 0x13};
    assert(nfc_cos_create_file(0x3F00, 0x0101, NFC_COS_FILE_TYPE_EF_BINARY,
                               2, 0, NULL, 0, bin_data, sizeof(bin_data)) == STATUS_SUCCESS);
    assert(nfc_cos_set_write_enabled(false) == STATUS_SUCCESS);
    assert(nfc_cos_create_file(0x3F00, 0x0102, NFC_COS_FILE_TYPE_EF_BINARY,
                               3, 0, NULL, 0, bin_data, sizeof(bin_data)) == STATUS_CMD_ERR);
    assert(nfc_cos_delete_file(0x0101) == STATUS_CMD_ERR);
    assert(nfc_cos_set_write_enabled(true) == STATUS_SUCCESS);

    const uint8_t read_sfi[] = {0x00, 0xB0, 0x82, 0x00, 0x04};
    uint16_t len = nfc_cos_process_apdu(read_sfi, sizeof(read_sfi), resp, sizeof(resp));
    const uint8_t read_sfi_want[] = {0x10, 0x11, 0x12, 0x13, 0x90, 0x00};
    expect_hex(resp, len, read_sfi_want, sizeof(read_sfi_want));

    const uint8_t upd[] = {0x00, 0xD6, 0x82, 0x02, 0x03, 0xAA, 0xBB, 0xCC};
    len = nfc_cos_process_apdu(upd, sizeof(upd), resp, sizeof(resp));
    const uint8_t ok[] = {0x90, 0x00};
    expect_hex(resp, len, ok, sizeof(ok));

    const uint8_t read_after[] = {0x00, 0xB0, 0x82, 0x00, 0x05};
    len = nfc_cos_process_apdu(read_after, sizeof(read_after), resp, sizeof(resp));
    const uint8_t read_after_want[] = {0x10, 0x11, 0xAA, 0xBB, 0xCC, 0x90, 0x00};
    expect_hex(resp, len, read_after_want, sizeof(read_after_want));

    static uint8_t big_data[5000];
    uint8_t big_read[24];
    uint16_t big_read_len = 0;
    for (uint16_t i = 0; i < sizeof(big_data); i++) big_data[i] = (uint8_t)(i & 0xFF);
    assert(nfc_cos_create_file(0x3F00, 0x0202, NFC_COS_FILE_TYPE_EF_BINARY,
                               6, 0, NULL, 0, big_data, sizeof(big_data)) == STATUS_SUCCESS);
    assert(nfc_cos_read_file(0x0202, 4090, sizeof(big_read),
                             big_read, &big_read_len, sizeof(big_read)) == STATUS_SUCCESS);
    assert(big_read_len == sizeof(big_read));
    for (uint16_t i = 0; i < sizeof(big_read); i++) {
        assert(big_read[i] == (uint8_t)((4090 + i) & 0xFF));
    }
    const uint8_t select_big_ef[] = {0x00, 0xA4, 0x00, 0x00, 0x02, 0x02, 0x02};
    len = nfc_cos_process_apdu(select_big_ef, sizeof(select_big_ef), resp, sizeof(resp));
    expect_hex(resp, len, ok, sizeof(ok));
    const uint8_t read_big_256[] = {0x00, 0xB0, 0x00, 0x00, 0x00};
    len = nfc_cos_process_apdu(read_big_256, sizeof(read_big_256), resp, sizeof(resp));
    assert(len == 258);
    for (uint16_t i = 0; i < 256; i++) assert(resp[i] == (uint8_t)(i & 0xFF));
    assert(resp[256] == 0x90 && resp[257] == 0x00);

    uint8_t rec[18];
    for (uint8_t i = 0; i < sizeof(rec); i++) rec[i] = (uint8_t)(i + 1);
    assert(nfc_cos_create_file(0x3F00, 0x0004, NFC_COS_FILE_TYPE_EF_RECORD,
                               4, 18, NULL, 0, NULL, 0) == STATUS_SUCCESS);
    assert(nfc_cos_create_file(0x3F00, 0x0005, NFC_COS_FILE_TYPE_EF_RECORD,
                               5, 18, NULL, 0, rec, 17) == STATUS_PAR_ERR);
    assert(nfc_cos_append_record(0x0004, rec, sizeof(rec)) == STATUS_SUCCESS);
    assert(nfc_cos_append_record(0x0004, rec, sizeof(rec) - 1) == STATUS_PAR_ERR);

    const uint8_t read_record[] = {0x00, 0xB2, 0x01, 0x24, 0x12};
    len = nfc_cos_process_apdu(read_record, sizeof(read_record), resp, sizeof(resp));
    uint8_t record_want[20];
    memcpy(record_want, rec, sizeof(rec));
    record_want[18] = 0x90;
    record_want[19] = 0x00;
    expect_hex(resp, len, record_want, sizeof(record_want));

    const uint8_t read_record_le0[] = {0x00, 0xB2, 0x01, 0x24, 0x00};
    len = nfc_cos_process_apdu(read_record_le0, sizeof(read_record_le0), resp, sizeof(resp));
    expect_hex(resp, len, record_want, sizeof(record_want));

    const uint8_t read_record_bad_len[] = {0x00, 0xB2, 0x01, 0x24, 0x11};
    len = nfc_cos_process_apdu(read_record_bad_len, sizeof(read_record_bad_len), resp, sizeof(resp));
    const uint8_t want_6c12[] = {0x6C, 0x12};
    expect_hex(resp, len, want_6c12, sizeof(want_6c12));

    const uint8_t read_record_bad_p2[] = {0x00, 0xB2, 0x01, 0x20, 0x12};
    len = nfc_cos_process_apdu(read_record_bad_p2, sizeof(read_record_bad_p2), resp, sizeof(resp));
    const uint8_t want_6a86[] = {0x6A, 0x86};
    expect_hex(resp, len, want_6a86, sizeof(want_6a86));

    const uint8_t read_record_on_binary_sfi[] = {0x00, 0xB2, 0x01, 0x14, 0x12};
    len = nfc_cos_process_apdu(read_record_on_binary_sfi, sizeof(read_record_on_binary_sfi), resp, sizeof(resp));
    const uint8_t want_6981[] = {0x69, 0x81};
    expect_hex(resp, len, want_6981, sizeof(want_6981));

    const uint8_t select_record_ef[] = {0x00, 0xA4, 0x00, 0x00, 0x02, 0x00, 0x04};
    len = nfc_cos_process_apdu(select_record_ef, sizeof(select_record_ef), resp, sizeof(resp));
    expect_hex(resp, len, ok, sizeof(ok));

    const uint8_t read_binary_on_record[] = {0x00, 0xB0, 0x00, 0x00, 0x00};
    len = nfc_cos_process_apdu(read_binary_on_record, sizeof(read_binary_on_record), resp, sizeof(resp));
    expect_hex(resp, len, want_6981, sizeof(want_6981));

    uint8_t append_record_apdu[5 + 18];
    append_record_apdu[0] = 0x00;
    append_record_apdu[1] = 0xE2;
    append_record_apdu[2] = 0x00;
    append_record_apdu[3] = 0x20;
    append_record_apdu[4] = 18;
    for (uint8_t i = 0; i < 18; i++) append_record_apdu[5 + i] = (uint8_t)(0x80 + i);
    len = nfc_cos_process_apdu(append_record_apdu, sizeof(append_record_apdu), resp, sizeof(resp));
    expect_hex(resp, len, ok, sizeof(ok));

    uint8_t append_record_bad_apdu[5 + 17];
    append_record_bad_apdu[0] = 0x00;
    append_record_bad_apdu[1] = 0xE2;
    append_record_bad_apdu[2] = 0x00;
    append_record_bad_apdu[3] = 0x20;
    append_record_bad_apdu[4] = 17;
    memset(&append_record_bad_apdu[5], 0xAA, 17);
    len = nfc_cos_process_apdu(append_record_bad_apdu, sizeof(append_record_bad_apdu), resp, sizeof(resp));
    const uint8_t want_6700[] = {0x67, 0x00};
    expect_hex(resp, len, want_6700, sizeof(want_6700));

    uint8_t update_record_apdu[5 + 18];
    update_record_apdu[0] = 0x00;
    update_record_apdu[1] = 0xDC;
    update_record_apdu[2] = 0x02;
    update_record_apdu[3] = 0x24;
    update_record_apdu[4] = 18;
    for (uint8_t i = 0; i < 18; i++) update_record_apdu[5 + i] = (uint8_t)(0x40 + i);
    len = nfc_cos_process_apdu(update_record_apdu, sizeof(update_record_apdu), resp, sizeof(resp));
    expect_hex(resp, len, ok, sizeof(ok));

    const uint8_t read_second_record[] = {0x00, 0xB2, 0x02, 0x24, 0x12};
    len = nfc_cos_process_apdu(read_second_record, sizeof(read_second_record), resp, sizeof(resp));
    for (uint8_t i = 0; i < 18; i++) record_want[i] = (uint8_t)(0x40 + i);
    expect_hex(resp, len, record_want, sizeof(record_want));

    update_record_apdu[2] = 0x03;
    len = nfc_cos_process_apdu(update_record_apdu, sizeof(update_record_apdu), resp, sizeof(resp));
    const uint8_t want_6a83[] = {0x6A, 0x83};
    expect_hex(resp, len, want_6a83, sizeof(want_6a83));

    const uint8_t challenge[] = {0x00, 0x84, 0x00, 0x00, 0x08};
    len = nfc_cos_process_apdu(challenge, sizeof(challenge), resp, sizeof(resp));
    assert(len == 10);
    assert(resp[8] == 0x90 && resp[9] == 0x00);

    const uint8_t aid[] = {0xA0, 0x00, 0x00, 0x01};
    const uint8_t aid_fci[] = {
        0x6F, 0x14, 0x84, 0x04, 0xA0, 0x00, 0x00, 0x01,
        0xA5, 0x0C, 0x9F, 0x08, 0x01, 0x02, 0x9F, 0x0C,
        0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x90, 0x00,
    };
    assert(nfc_cos_create_file(0x3F00, 0x1001, NFC_COS_FILE_TYPE_DF,
                               0, 0, aid, sizeof(aid), NULL, 0) == STATUS_SUCCESS);
    const uint8_t select_aid[] = {0x00, 0xA4, 0x04, 0x00, 0x04, 0xA0, 0x00, 0x00, 0x01, 0x00};
    len = nfc_cos_process_apdu(select_aid, sizeof(select_aid), resp, sizeof(resp));
    expect_hex(resp, len, aid_fci, sizeof(aid_fci));

    const uint8_t root_one[] = {0x31};
    const uint8_t child_one[] = {0x32, 0x33};
    uint8_t child_two[32];
    for (uint8_t i = 0; i < sizeof(child_two); i++) child_two[i] = (uint8_t)(0xA0 + i);
    assert(nfc_cos_create_file(0x3F00, 0x0001, NFC_COS_FILE_TYPE_EF_BINARY,
                               0, 0, NULL, 0, root_one, sizeof(root_one)) == STATUS_SUCCESS);
    assert(nfc_cos_create_file(0x1001, 0x0001, NFC_COS_FILE_TYPE_EF_BINARY,
                               0, 0, NULL, 0, child_one, sizeof(child_one)) == STATUS_SUCCESS);
    assert(nfc_cos_create_file(0x1001, 0x0002, NFC_COS_FILE_TYPE_EF_BINARY,
                               0, 0, NULL, 0, child_two, sizeof(child_two)) == STATUS_SUCCESS);

    const uint8_t select_mf[] = {0x00, 0xA4, 0x00, 0x00, 0x02, 0x3F, 0x00};
    len = nfc_cos_process_apdu(select_mf, sizeof(select_mf), resp, sizeof(resp));
    expect_hex(resp, len, ok, sizeof(ok));
    const uint8_t select_dup_ef[] = {0x00, 0xA4, 0x00, 0x00, 0x02, 0x00, 0x01};
    len = nfc_cos_process_apdu(select_dup_ef, sizeof(select_dup_ef), resp, sizeof(resp));
    expect_hex(resp, len, ok, sizeof(ok));
    const uint8_t read_one[] = {0x00, 0xB0, 0x00, 0x00, 0x01};
    len = nfc_cos_process_apdu(read_one, sizeof(read_one), resp, sizeof(resp));
    const uint8_t root_one_want[] = {0x31, 0x90, 0x00};
    expect_hex(resp, len, root_one_want, sizeof(root_one_want));

    const uint8_t select_df_1001[] = {0x00, 0xA4, 0x00, 0x00, 0x02, 0x10, 0x01};
    len = nfc_cos_process_apdu(select_df_1001, sizeof(select_df_1001), resp, sizeof(resp));
    expect_hex(resp, len, aid_fci, sizeof(aid_fci));
    const uint8_t read_child_two_by_sfi[] = {0x00, 0xB0, 0x82, 0x00, 0x20};
    len = nfc_cos_process_apdu(read_child_two_by_sfi, sizeof(read_child_two_by_sfi), resp, sizeof(resp));
    uint8_t child_two_want[34];
    memcpy(child_two_want, child_two, sizeof(child_two));
    child_two_want[32] = 0x90;
    child_two_want[33] = 0x00;
    expect_hex(resp, len, child_two_want, sizeof(child_two_want));
    len = nfc_cos_process_apdu(select_dup_ef, sizeof(select_dup_ef), resp, sizeof(resp));
    expect_hex(resp, len, ok, sizeof(ok));
    const uint8_t read_two[] = {0x00, 0xB0, 0x00, 0x00, 0x02};
    len = nfc_cos_process_apdu(read_two, sizeof(read_two), resp, sizeof(resp));
    const uint8_t child_one_want[] = {0x32, 0x33, 0x90, 0x00};
    expect_hex(resp, len, child_one_want, sizeof(child_one_want));

    assert(nfc_cos_set_write_enabled(false) == STATUS_SUCCESS);
    assert(nfc_cos_data_factory(0, TAG_TYPE_HF14A_COS));
    assert(nfc_cos_is_write_enabled());

    printf("cos_host_test: ok\n");
    return 0;
}
