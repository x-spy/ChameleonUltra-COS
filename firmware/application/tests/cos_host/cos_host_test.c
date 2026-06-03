#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "app_status.h"
#include "nfc_cos.h"

void nfc_tag_14a_set_handler(nfc_tag_14a_handler_t *handler) {
    (void)handler;
}

void nfc_tag_14a_tx_bytes(uint8_t *data, uint32_t bytes, bool appendCrc) {
    (void)data;
    (void)bytes;
    (void)appendCrc;
}

bool is_valid_uid_size(uint8_t uid_length) {
    return uid_length == NFC_TAG_14A_UID_SINGLE_SIZE ||
           uid_length == NFC_TAG_14A_UID_DOUBLE_SIZE ||
           uid_length == NFC_TAG_14A_UID_TRIPLE_SIZE;
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

    srand(1);
    assert(nfc_cos_data_loadcb(TAG_TYPE_HF14A_COS, &buffer) == (int)sizeof(info));
    assert(nfc_cos_is_write_enabled());

    const uint8_t bin_data[] = {0x10, 0x11, 0x12, 0x13};
    assert(nfc_cos_create_file(0x3F00, 0x0101, NFC_COS_FILE_TYPE_EF_BINARY,
                               2, 0, NULL, 0, bin_data, sizeof(bin_data)) == STATUS_SUCCESS);

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

    assert(nfc_cos_create_file(0x3F00, 0x0201, NFC_COS_FILE_TYPE_EF_RECORD,
                               4, 0, NULL, 0, NULL, 0) == STATUS_SUCCESS);
    uint8_t rec[18];
    for (uint8_t i = 0; i < sizeof(rec); i++) rec[i] = (uint8_t)(i + 1);
    assert(nfc_cos_append_record(0x0201, rec, sizeof(rec)) == STATUS_SUCCESS);

    const uint8_t read_record[] = {0x00, 0xB2, 0x01, 0x24, 0x12};
    len = nfc_cos_process_apdu(read_record, sizeof(read_record), resp, sizeof(resp));
    uint8_t record_want[20];
    memcpy(record_want, rec, sizeof(rec));
    record_want[18] = 0x90;
    record_want[19] = 0x00;
    expect_hex(resp, len, record_want, sizeof(record_want));

    const uint8_t challenge[] = {0x00, 0x84, 0x00, 0x00, 0x08};
    len = nfc_cos_process_apdu(challenge, sizeof(challenge), resp, sizeof(resp));
    assert(len == 10);
    assert(resp[8] == 0x90 && resp[9] == 0x00);

    const uint8_t aid[] = {0xA0, 0x00, 0x00, 0x01};
    assert(nfc_cos_create_file(0x3F00, 0x1001, NFC_COS_FILE_TYPE_DF,
                               0, 0, aid, sizeof(aid), NULL, 0) == STATUS_SUCCESS);
    const uint8_t select_aid[] = {0x00, 0xA4, 0x04, 0x00, 0x04, 0xA0, 0x00, 0x00, 0x01, 0x00};
    len = nfc_cos_process_apdu(select_aid, sizeof(select_aid), resp, sizeof(resp));
    assert(len >= 2);
    assert(resp[len - 2] == 0x90 && resp[len - 1] == 0x00);

    printf("cos_host_test: ok\n");
    return 0;
}
