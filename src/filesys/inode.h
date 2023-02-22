#ifndef FILESYS_INODE_H
#define FILESYS_INODE_H

#include <stdbool.h>
#include "filesys/off_t.h"
#include "devices/block.h"

struct bitmap;

void inode_init(void);
bool inode_create(block_sector_t, off_t);
bool inode_create_with_dir_info(block_sector_t, off_t, block_sector_t, bool);
struct inode* inode_open(block_sector_t);
struct inode* inode_reopen(struct inode*);
block_sector_t inode_get_inumber(const struct inode*);
void inode_close(struct inode*);
void inode_remove(struct inode*);
off_t inode_read_at(struct inode*, void*, off_t size, off_t offset);
off_t inode_write_at(struct inode*, const void*, off_t size, off_t offset);
void inode_deny_write(struct inode*);
void inode_allow_write(struct inode*);
off_t inode_length(const struct inode*);
bool inode_is_dir(const struct inode*);
bool inode_is_remove(const struct inode*);
block_sector_t inode_get_parent_dir(const struct inode*);

/* Core cache interface. */
void buffer_cache_init(void);
void buffer_cache_read(block_sector_t sector, void* buffer);
void buffer_cache_write(block_sector_t sector, const void* buffer);
void buffer_cache_flush(void);

#endif /* filesys/inode.h */
