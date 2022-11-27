#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>


void syscall_exit(struct intr_frame* f, int status) {
  f->eax = status;
  struct thread* cur = thread_current();
  if (cur != NULL)
    cur->ret_status = status;
  printf("%s: exit(%d)\n", cur->pcb->process_name, status);
  process_exit();
}

static bool is_validity(struct intr_frame* f, const uint8_t* uaddr) {
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
  if (pid == TID_ERROR) {
    syscall_exit(f, -1);
    return;
  }

  struct thread* child_thread = get_thread(pid);
  if (child_thread == NULL || !child_thread->load_success) {
    f->eax = TID_ERROR;
    return;
  }
  f->eax = pid;
}

static void syscall_wait(struct intr_frame* f, pid_t pid) {
  int ret = process_wait(pid);
  if (ret == TID_ERROR) {
    f->eax = -1;
    return;
  }
  f->eax = ret;
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

  struct file* opened_file = filesys_open(file);
  if (opened_file == NULL) {
    f->eax = -1;
    return;
  }
  f->eax = get_file_fd(opened_file);
}

static void syscall_file_size(struct intr_frame* f, int fd) {
  struct file* file = get_file(fd);
  if (file == NULL) {
    f->eax = -1;
    return;
  }
  f->eax = file_length(file);
}

static void syscall_read(struct intr_frame* f, int fd, void* buffer, unsigned size) {
  if (!is_validity(f, buffer))
    return;
  if (fd == 0) {
    char** buffer_vector = (char**)buffer;
    for (int i = 0; i < size; i++) {
      uint8_t inputc = input_getc();
      buffer_vector[i] = inputc;
    }
    f->eax = size;
    return;
  }
  struct file* file = get_file(fd);
  if (file == NULL) {
    f->eax = -1;
    return;
  }
  f->eax = file_read(file, buffer, size);
}

static void syscall_write(struct intr_frame* f, int fd, const void* buffer, unsigned size) {
  if (!is_validity(f, buffer))
    return;
  if (fd == 1) {
    putbuf((const char*)buffer, size);
    f->eax = size;
    return;
  }
  struct file* file = get_file(fd);
  if (file == NULL) {
    f->eax = -1;
    return;
  }
  f->eax = file_write(file, buffer, size);
}

static void syscall_seek(struct intr_frame* f, int fd, unsigned position) {
  struct file* file = get_file(fd);
  if (file == NULL) {
    f->eax = -1;
    return;
  }
  f->eax = file_seek(file, position);
}

static void syscall_tell(struct intr_frame* f, int fd) {
  struct file* file = get_file(fd);
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

static void syscall_handler(struct intr_frame*);

void syscall_init(void) { intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall"); }

static void syscall_handler(struct intr_frame* f UNUSED) {
  uint32_t* args = ((uint32_t*)f->esp);
  if (!is_validity(f, args) || !is_validity(f, args + 0x04))
    return;
  int syscall_type = args[0];
  switch (syscall_type) {
    case SYS_READ:
    case SYS_WRITE:
      if (!is_validity(f, args + 0x10))
        return;
    case SYS_CREATE:
    case SYS_SEEK:
      if (!is_validity(f, args + 0x0c))
        return;
    case SYS_EXIT:
    case SYS_EXEC:
    case SYS_WAIT:
    case SYS_REMOVE:
    case SYS_OPEN:
    case SYS_FILESIZE:
    case SYS_TELL:
    case SYS_CLOSE:
    case SYS_PRACTICE: {
      if (!is_validity(f, args + 0x08))
        return;
    } break;
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
      syscall_exec(f, args[1]);
      break;
    case SYS_WAIT:
      syscall_wait(f, args[1]);
      break;
    case SYS_CREATE:
      syscall_create(f, args[1], args[2]);
      break;
    case SYS_REMOVE:
      syscall_remove(f, args[1]);
      break;
    case SYS_OPEN:
      syscall_open(f, args[1]);
      break;
    case SYS_FILESIZE:
      syscall_file_size(f, args[1]);
      break;
    case SYS_READ:
      syscall_read(f, args[1], args[2], args[3]);
      break;
    case SYS_WRITE:
      syscall_write(f, args[1], args[2], args[3]);
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
    default:
      break;
  }
}