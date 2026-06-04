#ifndef COS_HOST_STUB_FDS_UTIL_H
#define COS_HOST_STUB_FDS_UTIL_H

#include <stdbool.h>
#include <stdint.h>

typedef struct {
    uint16_t id;
    uint16_t key;
} fds_slot_record_map_t;

static inline bool fds_read_sync(uint16_t id, uint16_t key, uint16_t *len, uint8_t *data) {
    (void)id;
    (void)key;
    (void)data;
    if (len != NULL) *len = 0;
    return false;
}

static inline bool fds_write_sync(uint16_t id, uint16_t key, uint16_t len, const void *data) {
    (void)id;
    (void)key;
    (void)len;
    (void)data;
    return true;
}

static inline int fds_delete_sync(uint16_t id, uint16_t key) {
    (void)id;
    (void)key;
    return 0;
}

static inline void get_fds_map_by_slot_sense_type_for_dump(uint8_t slot, uint8_t sense_type,
                                                           fds_slot_record_map_t *map) {
    map->id = 0x1100u + slot;
    map->key = sense_type;
}

#endif
