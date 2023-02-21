#ifndef FILESYS_DIRECTORY_H
#define FILESYS_DIRECTORY_H

#include <stdbool.h>
#include <stddef.h>
#include "devices/block.h"
#include "filesys/off_t.h"

/* Maximum length of a file name component.
   This is the traditional UNIX maximum length.
   After directories are implemented, this maximum length may be
   retained, but much longer full path names must be allowed. */
#define NAME_MAX 14

struct inode;

/* Opening and closing directories. */
bool dir_create(block_sector_t sector, size_t entry_cnt, block_sector_t parent_sector);
struct dir* dir_open(struct inode*);
struct dir* dir_open_pos(struct inode*, off_t pos);
struct dir* dir_parent_open(struct inode*);
struct dir* dir_open_cwd(const char*);
struct dir* dir_open_root(void);
struct dir* dir_reopen(struct dir*);
void dir_close(struct dir*);
struct inode* dir_get_inode(struct dir*);
struct inode* get_root_dir_inode(void);

off_t dir_tell(struct dir*);

/* Reading and writing. */
bool dir_lookup(const struct dir*, const char* name, struct inode**);
bool dir_add(struct dir*, const char* name, block_sector_t);
bool dir_remove(struct dir*, const char* name);
bool dir_remove_by_sector(struct dir*, const block_sector_t sector);
bool dir_readdir(struct dir*, char name[NAME_MAX + 1]);
bool dir_is_valid(struct dir*);
bool dir_is_empty(struct inode*);
void dir_free(struct dir*);

block_sector_t get_dir_inumber(const struct dir*);

#endif /* filesys/directory.h */
