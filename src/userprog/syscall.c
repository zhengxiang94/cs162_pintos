#include "userprog/syscall.h"
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "pagedir.h"
#include "stddef.h"
#include "threads/thread.h"
#include <stdio.h>
#include <float.h>
#include <syscall-nr.h>

void syscall_exit(struct intr_frame* f, int status) {
  f->eax = status;
  struct thread* cur = thread_current();
  set_ret_status(cur, status);
  printf("%s: exit(%d)\n", cur->pcb->process_name, status);
  process_exit();
}

static bool is_validity(struct intr_frame* f, const char* uaddr) {
  if (!is_user_vaddr(uaddr) || (pagedir_get_page(thread_current()->pcb->pagedir, uaddr) == NULL)) {
    syscall_exit(f, -1);
    return false;
  }

  return true;
}

static void syscall_exec(struct intr_frame* f, const char* cmd_line) {
  if (!is_validity(f, cmd_line) || !is_validity(f, cmd_line + 0x04))
    return;
  pid_t pid = process_execute(cmd_line);
  f->eax = pid;
}

static void syscall_create(struct intr_frame* f, const char* file, unsigned initial_size) {
  if (!is_validity(f, file))
    return;
  f->eax = filesys_create(file, initial_size);
}

static void syscall_remove(struct intr_frame* f, const char* file) {
  if (!is_validity(f, file))
    return;
  f->eax = filesys_remove(file);
}

static void syscall_open(struct intr_frame* f, const char* file) {
  if (!is_validity(f, file))
    return;
  f->eax = open_for_syscall(file);
}

static void syscall_file_size(struct intr_frame* f, int fd) {
  struct file* file = fd_to_file(fd);
  if (file == NULL) {
    f->eax = -1;
    return;
  }
  f->eax = file_length(file);
}

static int syscall_read(int fd, void* buffer, unsigned size) {
  if (fd == 0) {
    char* buffer_vector = (char*)buffer;
    for (unsigned i = 0; i < size; i++) {
      uint8_t inputc = input_getc();
      buffer_vector[i] = inputc;
    }
    return size;
  }

  struct process* pcb = thread_current()->pcb;
  if (pcb == NULL)
    return -1;
  struct file* file = fd_to_file(fd);
  if (file == NULL)
    return -1;
  lock_acquire(&pcb->file_list_lock);
  int ret = file_read(file, buffer, size);
  lock_release(&pcb->file_list_lock);
  return ret;
}

static int syscall_write(int fd, const void* buffer, unsigned size) {
  if (fd == 1) {
    putbuf((const char*)buffer, size);
    return size;
  }

  struct file* file = fd_to_file(fd);
  if (file == NULL)
    return -1;
  struct process* pcb = thread_current()->pcb;
  if (pcb == NULL)
    return -1;
  lock_acquire(&pcb->file_list_lock);
  int write_size = file_write(file, buffer, size);
  lock_release(&pcb->file_list_lock);
  return write_size;
}

static void syscall_seek(struct intr_frame* f, int fd, unsigned position) {
  struct file* file = fd_to_file(fd);
  if (file == NULL) {
    f->eax = -1;
    return;
  }
  file_seek(file, position);
}

static void syscall_tell(struct intr_frame* f, int fd) {
  struct file* file = fd_to_file(fd);
  if (file == NULL) {
    f->eax = -1;
    return;
  }
  f->eax = file_tell(file);
}

static void syscall_close(struct intr_frame* f, int fd) {
  if (!close_file(fd)) {
    f->eax = -1;
    return;
  }
}

static bool syscall_chdir(const char* dir) {
  block_sector_t new_cwd = filesys_chdir(dir);
  if (new_cwd == 0)
    return false;
  thread_current()->cwd = new_cwd;
  return true;
}

static bool syscall_mkdir(const char* dir) { return filesys_mkdir(dir); }

static bool syscall_readdir(int fd, char* name) {
  struct file* file = fd_to_file(fd);
  if (file == NULL) {
    return false;
  }
  return filesys_readdir(file, name);
}

static bool syscall_isdir(int fd) {
  struct file* file = fd_to_file(fd);
  if (file == NULL) {
    return false;
  }
  return filesys_isdir(file);
}

static int syscall_inumber(int fd) {
  struct file* file = fd_to_file(fd);
  if (file == NULL)
    return -1;
  return file_get_inumber(file);
}

static void syscall_handler(struct intr_frame*);

void syscall_init(void) { intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall"); }

static void syscall_handler(struct intr_frame* f UNUSED) {
  uint32_t* args = ((uint32_t*)f->esp);
  if (!is_validity(f, (char*)args) || !is_validity(f, (char*)(args + 0x04)))
    return;
  int syscall_type = args[0];
  switch (syscall_type) {
    case SYS_READ:
    case SYS_WRITE:
      if (!is_validity(f, (char*)args[2]))
        return;
    case SYS_PT_CREATE:
      if (!is_validity(f, (char*)(args + 0x10)))
        return;
    case SYS_CREATE:
    case SYS_SEEK:
    case SYS_SEMA_INIT:
    case SYS_READDIR:
      if (!is_validity(f, (char*)(args + 0x0c)))
        return;
    case SYS_EXIT:
    case SYS_EXEC:
    case SYS_WAIT:
    case SYS_REMOVE:
    case SYS_OPEN:
    case SYS_FILESIZE:
    case SYS_TELL:
    case SYS_CLOSE:
    case SYS_PRACTICE:
    case SYS_COMPUTE_E:
    case SYS_PT_JOIN:
    case SYS_LOCK_INIT:
    case SYS_LOCK_ACQUIRE:
    case SYS_LOCK_RELEASE:
    case SYS_SEMA_DOWN:
    case SYS_SEMA_UP:
    case SYS_GET_TID:
    case SYS_CHDIR:
    case SYS_MKDIR:
    case SYS_ISDIR:
    case SYS_INUMBER: {
      if (!is_validity(f, (char*)(args + 0x08)))
        return;
    } break;
    case SYS_PT_EXIT:
    default:
      break;
  }

  /*
   * The following print statement, if uncommented, will print out the syscall
   * number whenever a process enters a system call. You might find it useful
   * when debugging. It will cause tests to fail, however, so you should not
   * include it in your final submission.
   */

  /* printf("System call number: %d\n", args[0]); */
  switch (syscall_type) {
    case SYS_HALT:
      shutdown_power_off();
      break;
    case SYS_EXIT:
      syscall_exit(f, args[1]);
      break;
    case SYS_EXEC:
      syscall_exec(f, (char*)args[1]);
      break;
    case SYS_WAIT:
      f->eax = process_wait(args[1]);
      break;
    case SYS_CREATE:
      syscall_create(f, (char*)args[1], args[2]);
      break;
    case SYS_REMOVE:
      syscall_remove(f, (char*)args[1]);
      break;
    case SYS_OPEN:
      syscall_open(f, (char*)args[1]);
      break;
    case SYS_FILESIZE:
      syscall_file_size(f, args[1]);
      break;
    case SYS_READ:
      f->eax = syscall_read(args[1], (char*)args[2], args[3]);
      break;
    case SYS_WRITE:
      f->eax = syscall_write(args[1], (char*)args[2], args[3]);
      break;
    case SYS_SEEK:
      syscall_seek(f, args[1], args[2]);
      break;
    case SYS_TELL:
      syscall_tell(f, args[1]);
      break;
    case SYS_CLOSE:
      syscall_close(f, args[1]);
      break;
    case SYS_PRACTICE:
      f->eax = (int)args[1] + 1;
      break;
    case SYS_COMPUTE_E:
      f->eax = sys_sum_to_e((int)args[1]);
      break;
    case SYS_PT_CREATE:
      f->eax = pthread_execute((stub_fun)args[1], (pthread_fun)args[2], (void*)args[3]);
      break;
    case SYS_PT_EXIT:
      pthread_exit();
      break;
    case SYS_PT_JOIN:
      f->eax = pthread_join((tid_t)args[1]);
      break;
    case SYS_LOCK_INIT:
      f->eax = syscall_lock_init((char*)args[1]);
      break;
    case SYS_LOCK_ACQUIRE:
      f->eax = syscall_lock_acquire((char*)args[1]);
      break;
    case SYS_LOCK_RELEASE:
      f->eax = syscall_lock_release((char*)args[1]);
      break;
    case SYS_SEMA_INIT:
      f->eax = syscall_sema_init((char*)args[1], (int)args[2]);
      break;
    case SYS_SEMA_DOWN:
      f->eax = syscall_sema_down((char*)args[1]);
      break;
    case SYS_SEMA_UP:
      f->eax = syscall_sema_up((char*)args[1]);
      break;
    case SYS_GET_TID:
      f->eax = thread_current()->tid;
      break;
    case SYS_CHDIR:
      f->eax = syscall_chdir((char*)args[1]);
      break;
    case SYS_MKDIR:
      f->eax = syscall_mkdir((char*)args[1]);
      break;
    case SYS_READDIR:
      f->eax = syscall_readdir((int)args[1], (char*)args[2]);
      break;
    case SYS_ISDIR:
      f->eax = syscall_isdir((int)args[1]);
      break;
    case SYS_INUMBER:
      f->eax = syscall_inumber((int)args[1]);
      break;
    default:
      break;
  }
}