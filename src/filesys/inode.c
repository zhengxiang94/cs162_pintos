#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <stddef.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "filesys/off_t.h"
#include "stdbool.h"
#include "threads/malloc.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

#define NUM_DIRECT 122
#define NUM_INDIRECT 128
#define NUM_DIRECT_PLUS_INDIRECT 250 // NUM_DIRECT + NUM_INDIRECT
#define MAX_BLOCK 16384              // 128 * 128
#define MAX_LENGTH 8388608           // 128 * 128 * 512

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk {
  block_sector_t parent_dir;      /* inode_disk sector of the parent directory. */
  bool is_dir;                    /* True if this file is a directory. */
  off_t length;                   /* File size in bytes. */
  block_sector_t direct[122];     /* Direct pointers. */
  block_sector_t indirect;        /* Indirect pointer. */
  block_sector_t doubly_indirect; /* Doubly indirect pointer. */
  unsigned magic;                 /* Magic number. */
};

struct indirect_block {
  block_sector_t direct[128];
};

struct doubly_indirect_block {
  block_sector_t indirect_block[128];
};

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t bytes_to_sectors(off_t size) { return DIV_ROUND_UP(size, BLOCK_SECTOR_SIZE); }

/* In-memory inode. */
struct inode {
  struct list_elem elem;  /* Element in inode list. */
  block_sector_t sector;  /* Sector number of disk location. */
  int open_cnt;           /* Number of openers. */
  bool removed;           /* True if deleted, false otherwise. */
  int deny_write_cnt;     /* 0: writes ok, >0: deny writes. */
  struct inode_disk data; /* Inode content. */
};

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t byte_to_sector(const struct inode* inode, off_t pos) {
  ASSERT(inode != NULL);
  if (pos < inode->data.length) {
    size_t n_sector = pos / BLOCK_SECTOR_SIZE;
    if (n_sector < NUM_DIRECT)
      return inode->data.direct[n_sector];
    if (n_sector < NUM_DIRECT_PLUS_INDIRECT) {
      struct indirect_block* indirect_block = malloc(BLOCK_SECTOR_SIZE);
      block_read(fs_device, inode->data.indirect, indirect_block);
      block_sector_t indirect_sector = indirect_block->direct[n_sector - NUM_DIRECT];
      free(indirect_block);
      return indirect_sector;
    }

    struct doubly_indirect_block* doubly_indirect_block = malloc(BLOCK_SECTOR_SIZE);
    block_read(fs_device, inode->data.doubly_indirect, doubly_indirect_block);
    size_t n_indirect = (n_sector - NUM_DIRECT_PLUS_INDIRECT) / NUM_INDIRECT;
    block_sector_t indirect_block_sector = doubly_indirect_block->indirect_block[n_indirect];
    free(doubly_indirect_block);

    struct indirect_block indirect_block;
    block_read(fs_device, indirect_block_sector, &indirect_block);
    size_t index_indirect_block = (n_sector - NUM_DIRECT_PLUS_INDIRECT) % NUM_INDIRECT;
    if (indirect_block.direct[index_indirect_block] > 4096) {
      PANIC("byte_to_sector (pos=%" PRDSNu ", "
            "index_indirect_block=%" PRDSNu ")\n",
            pos, index_indirect_block);
    }

    return indirect_block.direct[index_indirect_block];
  } else
    return -1;
}

static void block_write_zero(block_sector_t sector) {
  static char zeros[BLOCK_SECTOR_SIZE];
  block_write(fs_device, sector, zeros);
}

static bool allocate_direct_blocks(struct inode_disk* inode, block_sector_t start,
                                   block_sector_t end) {
  ASSERT(end <= NUM_DIRECT);
  bool success = free_map_allocate(end - start, &inode->direct[start]);
  if (success) {
    block_write_zero(inode->direct[start]);
    for (block_sector_t i = start + 1, j = 1; i < end; i++, j++) {
      inode->direct[i] = inode->direct[start] + j;
      block_write_zero(inode->direct[i]);
    }
    return success;
  }
  for (block_sector_t i = start; i < end; i++) {
    if (!free_map_allocate(1, &inode->direct[i]))
      return false;
    block_write_zero(inode->direct[i]);
  }
  return true;
}

static void release_direct_blocks(struct inode_disk* inode, block_sector_t end) {
  ASSERT(end <= NUM_DIRECT);
  for (block_sector_t i = 0; i < end; i++)
    free_map_release(inode->direct[i], 1);
}

static bool allocate_indirect_block(struct indirect_block* indirect_block,
                                    block_sector_t indirect_start, block_sector_t indirect_end) {
  if (free_map_allocate(indirect_end - indirect_start, &indirect_block->direct[indirect_start])) {
    block_write_zero(indirect_block->direct[indirect_start]);
    for (block_sector_t i = indirect_start + 1, j = 1; i < indirect_end; i++, j++) {
      indirect_block->direct[i] = indirect_block->direct[indirect_start] + j;
      block_write_zero(indirect_block->direct[i]);
    }
  } else {
    for (block_sector_t i = indirect_start; i < indirect_end; i++) {
      if (!free_map_allocate(1, &indirect_block->direct[i]))
        return false;
      block_write_zero(indirect_block->direct[i]);
    }
  }
  return true;
}

static bool allocate_indirect_blocks(struct inode_disk* inode, block_sector_t start,
                                     block_sector_t end) {
  ASSERT(start >= NUM_DIRECT);
  ASSERT(end <= NUM_DIRECT_PLUS_INDIRECT);
  block_sector_t indirect_start = start - NUM_DIRECT;
  block_sector_t indirect_end = end - NUM_DIRECT;

  struct indirect_block* indirect_block = malloc(BLOCK_SECTOR_SIZE);
  block_read(fs_device, inode->indirect, indirect_block);

  bool success = allocate_indirect_block(indirect_block, indirect_start, indirect_end);
  if (success)
    block_write(fs_device, inode->indirect, indirect_block);

  free(indirect_block);
  return success;
}

static void release_indirect_blocks(struct inode_disk* inode, block_sector_t end) {
  ASSERT(end <= NUM_DIRECT_PLUS_INDIRECT);

  struct indirect_block* indirect_block = malloc(BLOCK_SECTOR_SIZE);
  block_read(fs_device, inode->indirect, indirect_block);

  block_sector_t indirect_end = end - NUM_DIRECT;
  for (size_t i = 0; i <= indirect_end; i++)
    free_map_release(indirect_block->direct[i], 1);
  free_map_release(inode->indirect, 1);
  free(indirect_block);
}

static bool allocate_doubly_indirect_blocks(struct inode_disk* inode, block_sector_t start,
                                            block_sector_t end) {
  ASSERT(start >= NUM_DIRECT_PLUS_INDIRECT);
  ASSERT(end <= MAX_BLOCK);
  struct doubly_indirect_block* doubly_indirect = malloc(BLOCK_SECTOR_SIZE);
  block_read(fs_device, inode->doubly_indirect, doubly_indirect);
  block_sector_t doubly_indirect_start = start - NUM_DIRECT_PLUS_INDIRECT;
  block_sector_t doubly_indirect_end = end - NUM_DIRECT_PLUS_INDIRECT;
  block_sector_t blocks_start = doubly_indirect_start / NUM_INDIRECT;
  block_sector_t blocks_end = doubly_indirect_end / NUM_INDIRECT;
  bool success = false;

  for (size_t i = blocks_start; i <= blocks_end; i++) {
    if (doubly_indirect->indirect_block[i] == 0) {
      success = free_map_allocate(1, &doubly_indirect->indirect_block[i]);
      if (!success)
        goto done;
    }

    struct indirect_block* indirect_block = malloc(BLOCK_SECTOR_SIZE);
    block_read(fs_device, doubly_indirect->indirect_block[i], indirect_block);

    block_sector_t indirect_start = i == blocks_start ? doubly_indirect_start % NUM_INDIRECT : 0;
    block_sector_t indirect_end =
        i == blocks_end ? doubly_indirect_end % NUM_INDIRECT : NUM_INDIRECT;
    success = allocate_indirect_block(indirect_block, indirect_start, indirect_end);
    if (!success) {
      free(indirect_block);
      goto done;
    }

    block_write(fs_device, doubly_indirect->indirect_block[i], indirect_block);
    free(indirect_block);
  }

  block_write(fs_device, inode->doubly_indirect, doubly_indirect);
done:
  free(doubly_indirect);
  return true;
}

static void release_doubly_indirect_blocks(struct inode_disk* inode, block_sector_t end) {
  ASSERT(end <= MAX_BLOCK);
  struct doubly_indirect_block* doubly_indirect = malloc(BLOCK_SECTOR_SIZE);
  block_read(fs_device, inode->doubly_indirect, doubly_indirect);

  block_sector_t doubly_indirect_end = end - NUM_DIRECT_PLUS_INDIRECT;
  block_sector_t blocks_end = doubly_indirect_end / NUM_INDIRECT;

  for (size_t i = 0; i <= blocks_end; i++) {
    struct indirect_block* indirect_block = malloc(BLOCK_SECTOR_SIZE);
    block_read(fs_device, doubly_indirect->indirect_block[i], indirect_block);

    if (i == blocks_end) {
      block_sector_t indirect_end = doubly_indirect_end % NUM_INDIRECT;
      for (size_t i = 0; i <= indirect_end; i++)
        free_map_release(indirect_block->direct[i], 1);
    } else {
      for (size_t i = 0; i < BLOCK_SECTOR_SIZE; i++)
        free_map_release(indirect_block->direct[i], 1);
    }

    free_map_release(doubly_indirect->indirect_block[i], 1);
    free(indirect_block);
  }

  free_map_release(inode->doubly_indirect, 1);
  free(doubly_indirect);
}

static bool inode_map_sectors_allocate(struct inode_disk* inode, block_sector_t start,
                                       block_sector_t end) {
  ASSERT(end <= MAX_BLOCK);
  ASSERT(end > start);
  if (end <= NUM_DIRECT) {
    return allocate_direct_blocks(inode, start, end);
  }

  if (start < NUM_DIRECT) {
    if (!allocate_direct_blocks(inode, start, NUM_DIRECT))
      return false;
    start = NUM_DIRECT;
  }

  if (end <= NUM_DIRECT_PLUS_INDIRECT) {
    return allocate_indirect_blocks(inode, start, end);
  }

  if (start < NUM_DIRECT_PLUS_INDIRECT) {
    if (!allocate_indirect_blocks(inode, start, NUM_DIRECT_PLUS_INDIRECT))
      return false;
    start = NUM_DIRECT_PLUS_INDIRECT;
  }

  return allocate_doubly_indirect_blocks(inode, start, end);
}

static void inode_map_sectors_release(struct inode_disk* inode, block_sector_t end) {
  ASSERT(end <= MAX_BLOCK);
  if (end <= NUM_DIRECT) {
    release_direct_blocks(inode, end);
    return;
  }
  release_direct_blocks(inode, NUM_DIRECT);
  if (end <= NUM_DIRECT_PLUS_INDIRECT) {
    return release_indirect_blocks(inode, end);
  }
  release_direct_blocks(inode, NUM_DIRECT_PLUS_INDIRECT);
  release_doubly_indirect_blocks(inode, end);
}

/* Extends the length of INODE to the LENGTH, allocating new
   sectors as needed. */
static bool extend_inode_length(struct inode_disk* inode, off_t length) {
  ASSERT(inode != NULL);
  ASSERT(length <= MAX_LENGTH);
  if (length == inode->length)
    return true;
  ASSERT(length > inode->length);

  size_t start = bytes_to_sectors(inode->length);
  size_t end = bytes_to_sectors(length);

  if (start == end) {
    inode->length = length;
    return true;
  }

  /* Acquire free map lock and check available space. */
  lock_acquire(&free_map_lock);
  if (free_map_available_space() < end - start + (end / NUM_DIRECT) - (start / NUM_DIRECT)) {
    lock_release(&free_map_lock);
    return false;
  }

  /* Allocate INDIRECT. */
  if (start <= NUM_DIRECT && NUM_DIRECT < end) {
    free_map_allocate(1, &inode->indirect);
    block_write_zero(inode->indirect);
  }

  /* Allocate DOUBLY_INDIRECT. */
  if (start <= NUM_DIRECT_PLUS_INDIRECT && NUM_DIRECT_PLUS_INDIRECT < end) {
    free_map_allocate(1, &inode->doubly_indirect);
    block_write_zero(inode->doubly_indirect);
  }

  /* Allocate all leaf nodes and set INODE's LENGTH. */
  bool success = inode_map_sectors_allocate(inode, start, end);
  lock_release(&free_map_lock);
  inode->length = length;
  return success;
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void inode_init(void) { list_init(&open_inodes); }

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool inode_create(block_sector_t sector, off_t length) {
  return inode_create_with_dir_info(sector, length, ROOT_DIR_SECTOR, false);
}

bool inode_create_with_dir_info(block_sector_t sector, off_t length, block_sector_t parent_dir,
                                bool is_dir) {
  struct inode_disk* disk_inode = NULL;
  bool success = false;

  ASSERT(length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT(sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode = calloc(1, sizeof *disk_inode);
  if (disk_inode != NULL) {
    disk_inode->parent_dir = parent_dir;
    disk_inode->is_dir = is_dir;
    disk_inode->length = 0;
    disk_inode->magic = INODE_MAGIC;
    if (extend_inode_length(disk_inode, length)) {
      block_write(fs_device, sector, disk_inode);
      success = true;
    }
    free(disk_inode);
  }
  return success;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode* inode_open(block_sector_t sector) {
  struct list_elem* e;
  struct inode* inode;

  /* Check whether this inode is already open. */
  for (e = list_begin(&open_inodes); e != list_end(&open_inodes); e = list_next(e)) {
    inode = list_entry(e, struct inode, elem);
    if (inode->sector == sector) {
      inode_reopen(inode);
      return inode;
    }
  }

  /* Allocate memory. */
  inode = malloc(sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  list_push_front(&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  block_read(fs_device, inode->sector, &inode->data);
  return inode;
}

/* Reopens and returns INODE. */
struct inode* inode_reopen(struct inode* inode) {
  if (inode != NULL)
    inode->open_cnt++;
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t inode_get_inumber(const struct inode* inode) { return inode->sector; }

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void inode_close(struct inode* inode) {
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0) {
    /* Remove from inode list and release lock. */
    list_remove(&inode->elem);

    /* Deallocate blocks if removed. */
    if (inode->removed) {
      free_map_release(inode->sector, 1);
      inode_map_sectors_release(&inode->data, bytes_to_sectors(inode->data.length));
    }

    free(inode);
  }
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void inode_remove(struct inode* inode) {
  ASSERT(inode != NULL);
  inode->removed = true;
}

bool inode_is_remove(const struct inode* inode) {
  ASSERT(inode != NULL);
  return inode->removed;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t inode_read_at(struct inode* inode, void* buffer_, off_t size, off_t offset) {
  uint8_t* buffer = buffer_;
  off_t bytes_read = 0;
  uint8_t* bounce = NULL;

  while (size > 0) {
    /* Disk sector to read, starting byte offset within sector. */
    block_sector_t sector_idx = byte_to_sector(inode, offset);
    int sector_ofs = offset % BLOCK_SECTOR_SIZE;

    /* Bytes left in inode, bytes left in sector, lesser of the two. */
    off_t inode_left = inode_length(inode) - offset;
    int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
    int min_left = inode_left < sector_left ? inode_left : sector_left;

    /* Number of bytes to actually copy out of this sector. */
    int chunk_size = size < min_left ? size : min_left;
    if (chunk_size <= 0)
      break;

    if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE) {
      /* Read full sector directly into caller's buffer. */
      block_read(fs_device, sector_idx, buffer + bytes_read);
    } else {
      /* Read sector into bounce buffer, then partially copy
             into caller's buffer. */
      if (bounce == NULL) {
        bounce = malloc(BLOCK_SECTOR_SIZE);
        if (bounce == NULL)
          break;
      }
      block_read(fs_device, sector_idx, bounce);
      memcpy(buffer + bytes_read, bounce + sector_ofs, chunk_size);
    }

    /* Advance. */
    size -= chunk_size;
    offset += chunk_size;
    bytes_read += chunk_size;
  }
  free(bounce);

  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t inode_write_at(struct inode* inode, const void* buffer_, off_t size, off_t offset) {
  off_t length = size + offset;
  if (length > MAX_LENGTH)
    return 0;
  if (length > inode->data.length) {
    if (!extend_inode_length(&inode->data, length))
      return 0;
    block_write(fs_device, inode->sector, &inode->data);
  }

  const uint8_t* buffer = buffer_;
  off_t bytes_written = 0;
  uint8_t* bounce = NULL;

  if (inode->deny_write_cnt)
    return 0;

  while (size > 0) {
    /* Sector to write, starting byte offset within sector. */
    block_sector_t sector_idx = byte_to_sector(inode, offset);
    int sector_ofs = offset % BLOCK_SECTOR_SIZE;

    /* Bytes left in inode, bytes left in sector, lesser of the two. */
    off_t inode_left = inode_length(inode) - offset;
    int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
    int min_left = inode_left < sector_left ? inode_left : sector_left;

    /* Number of bytes to actually write into this sector. */
    int chunk_size = size < min_left ? size : min_left;
    if (chunk_size <= 0)
      break;

    if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE) {
      /* Write full sector directly to disk. */
      block_write(fs_device, sector_idx, buffer + bytes_written);
    } else {
      /* We need a bounce buffer. */
      if (bounce == NULL) {
        bounce = malloc(BLOCK_SECTOR_SIZE);
        if (bounce == NULL)
          break;
      }

      /* If the sector contains data before or after the chunk
             we're writing, then we need to read in the sector
             first.  Otherwise we start with a sector of all zeros. */
      if (sector_ofs > 0 || chunk_size < sector_left)
        block_read(fs_device, sector_idx, bounce);
      else
        memset(bounce, 0, BLOCK_SECTOR_SIZE);
      memcpy(bounce + sector_ofs, buffer + bytes_written, chunk_size);
      block_write(fs_device, sector_idx, bounce);
    }

    /* Advance. */
    size -= chunk_size;
    offset += chunk_size;
    bytes_written += chunk_size;
  }
  free(bounce);

  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void inode_deny_write(struct inode* inode) {
  inode->deny_write_cnt++;
  ASSERT(inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void inode_allow_write(struct inode* inode) {
  ASSERT(inode->deny_write_cnt > 0);
  ASSERT(inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t inode_length(const struct inode* inode) { return inode->data.length; }

bool inode_is_dir(const struct inode* inode) { return inode != NULL && inode->data.is_dir; }

block_sector_t inode_get_parent_dir(const struct inode* inode) { return inode->data.parent_dir; }
