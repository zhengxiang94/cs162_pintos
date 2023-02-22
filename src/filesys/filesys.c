#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "stdbool.h"
#include "threads/thread.h"
#include "userprog/process.h"

/* Partition that contains the file system. */
struct block* fs_device;

static void do_format(void);

static int get_next_part(char part[NAME_MAX + 1], const char** srcp);

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void filesys_init(bool format) {
  fs_device = block_get_role(BLOCK_FILESYS);
  if (fs_device == NULL)
    PANIC("No file system device found, can't initialize file system.");

  inode_init();
  free_map_init();

  if (format)
    do_format();

  free_map_open();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void filesys_done(void) {
  buffer_cache_flush();
  free_map_close();
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool filesys_create(const char* name, off_t initial_size) {
  struct dir* dir = dir_open_cwd(name);
  struct inode* inode = NULL;
  const char** name_cp = &name;

  while (true) {
    if (!dir_is_valid(dir))
      return false;
    char part[NAME_MAX + 1];
    int status = get_next_part(part, name_cp);
    if (status < 1)
      return false;
    if (**name_cp == '\0') {
      block_sector_t inode_sector = 0;
      bool success =
          (free_map_allocate(1, &inode_sector) &&
           inode_create_with_dir_info(inode_sector, initial_size, get_dir_inumber(dir), false) &&
           dir_add(dir, part, inode_sector));
      if (!success && inode_sector != 0)
        free_map_release(inode_sector, 1);
      dir_close(dir);
      return success;
    }
    dir_lookup(dir, part, &inode);
    dir_close(dir);
    dir = dir_open(inode);
  }
  return false;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file* filesys_open(const char* name) {
  if (*name == '\0')
    return NULL;
  if (!strcmp(name, ".")) {
    struct inode* inode = inode_open(thread_current()->cwd);
    if (inode == NULL || inode_is_remove(inode))
      return NULL;
    return file_open(inode);
  }

  struct dir* dir = dir_open_cwd(name);
  struct inode* inode = NULL;
  const char** name_cp = &name;

  while (true) {
    char part[NAME_MAX + 1];
    int status = get_next_part(part, name_cp);
    if (0 == status)
      return file_open(dir_get_inode(dir));
    if (dir != NULL) {
      dir_lookup(dir, part, &inode);
    }
    dir_close(dir);
    if (**name_cp == '\0')
      break;
    dir = dir_open(inode);
  }
  return file_open(inode);
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool filesys_remove(const char* name) {
  struct file* file = filesys_open(name);
  if (file == NULL)
    return false;
  struct inode* inode = file_get_inode(file);
  if (inode == NULL)
    return false;
  if (inode_is_dir(inode)) {
    if (!dir_is_empty(inode))
      return false;
  }

  struct dir* dir = dir_parent_open(inode);
  bool success = dir != NULL && dir_remove_by_sector(dir, inode_get_inumber(inode));
  dir_close(dir);
  file_close(file);
  return success;
}

bool filesys_mkdir(const char* dir_name) {
  if (dir_name == NULL || ('\0' == dir_name[0]))
    return false;
  const char** name_cp = &dir_name;
  struct inode* inode = NULL;
  struct dir* dir = dir_open_cwd(dir_name);
  while (true) {
    char part[NAME_MAX + 1];
    get_next_part(part, name_cp);
    if (**name_cp == '\0') {
      block_sector_t inode_sector = 0;
      bool success = free_map_allocate(1, &inode_sector) &&
                     dir_create(inode_sector, 16, get_dir_inumber(dir)) &&
                     dir_add(dir, part, inode_sector);
      if (!success && inode_sector != 0)
        free_map_release(inode_sector, 1);
      dir_close(dir);
      return success;
    }

    if (dir != NULL) {
      dir_lookup(dir, part, &inode);
    }
    dir_close(dir);
    dir = dir_open(inode);
    if (dir == NULL)
      return false;
  }
  return true;
}

block_sector_t filesys_chdir(const char* path_name) {
  if (path_name == NULL || ('\0' == path_name[0]))
    return 0;
  if (!strcmp(path_name, ".."))
    return inode_get_parent_dir(inode_open(thread_current()->cwd));
  const char** name_cp = &path_name;
  struct dir* dir = dir_open_cwd(path_name);
  while (true) {
    struct inode* inode = NULL;
    char part[NAME_MAX + 1];
    get_next_part(part, name_cp);
    if (dir != NULL) {
      dir_lookup(dir, part, &inode);
    }
    dir_close(dir);
    if (**name_cp == '\0') {
      if (inode == NULL)
        return 0;
      return inode_get_inumber(inode);
    }
    if (inode == NULL)
      return 0;
    dir = dir_open(inode);
    if (dir == NULL)
      return 0;
  }
  return 0;
}

bool filesys_isdir(struct file* file) {
  struct inode* inode = file_get_inode(file);
  return inode != NULL && inode_is_dir(inode);
}

bool filesys_readdir(struct file* file, char* name) {
  struct inode* inode = file_get_inode(file);
  bool success = false;
  if (inode == NULL || !inode_is_dir(inode))
    return success;
  struct dir* dir = dir_open_pos(inode, file_tell(file));
  if (dir != NULL) {
    success = dir_readdir(dir, name);
    if (success)
      file_seek(file, dir_tell(dir));
  }
  dir_free(dir);
  return success;
}

/* Formats the file system. */
static void do_format(void) {
  printf("Formatting file system...");
  free_map_create();
  if (!dir_create(ROOT_DIR_SECTOR, 16, ROOT_DIR_SECTOR))
    PANIC("root directory creation failed");
  free_map_close();
  printf("done.\n");
}

/* Extracts a file name part from *SRCP into PART, and updates *SRCP so that the
   next call will return the next file name part. Returns 1 if successful, 0 at
   end of string, -1 for a too-long file name part. */
static int get_next_part(char part[NAME_MAX + 1], const char** srcp) {
  const char* src = *srcp;
  char* dst = part;

  /* Skip leading slashes.  If it's all slashes, we're done. */
  while (*src == '/')
    src++;
  if (*src == '\0')
    return 0;

  /* Copy up to NAME_MAX character from SRC to DST.  Add null terminator. */
  while (*src != '/' && *src != '\0') {
    if (dst < part + NAME_MAX)
      *dst++ = *src;
    else
      return -1;
    src++;
  }
  *dst = '\0';

  /* Advance source pointer. */
  *srcp = src;
  return 1;
}