#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"

static void syscall_exit(struct intr_frame* f, int status) {
  f->eax = status;
  printf("%s: exit(%d)\n", thread_current()->pcb->process_name, status);
  process_exit();
}

static void syscall_create(struct intr_frame* f, const char* file, unsigned initial_size) {
  f->eax = filesys_create(file, initial_size);
}

static void syscall_write(struct intr_frame* f, int fd, const void* buffer, unsigned size) {
  if (fd == 1) {
    putbuf((const char*)buffer, size);
    f->eax = size;
    return;
  } 
}

static void syscall_handler(struct intr_frame*);

void syscall_init(void) { intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall"); }

static void syscall_handler(struct intr_frame* f UNUSED) {
  uint32_t* args = ((uint32_t*)f->esp);

  /*
   * The following print statement, if uncommented, will print out the syscall
   * number whenever a process enters a system call. You might find it useful
   * when debugging. It will cause tests to fail, however, so you should not
   * include it in your final submission.
   */

  /* printf("System call number: %d\n", args[0]); */
  switch (args[0]) {
    case SYS_HALT:
      shutdown_power_off();
      break;
    case SYS_EXIT:
      syscall_exit(f, args[1]);
      break;
    case SYS_EXEC: {
      break;
    }
    case SYS_WAIT: {
      break;
    }
    case SYS_CREATE:
      syscall_create(f, args[1], args[2]);
      break;
    case SYS_REMOVE: {
      break;
    }
    case SYS_OPEN: {
      break;
    }
    case SYS_FILESIZE: {
      break;
    }
    case SYS_READ: {
      break;
    }
    case SYS_WRITE:
      syscall_write(f, args[1], args[2], args[3]);
      break;
    case SYS_SEEK: {
      break;
    }
    case SYS_TELL: {
      break;
    }
    case SYS_CLOSE: {
      break;
    }
    case SYS_PRACTICE:
      f->eax = (int)args[1] + 1;
      break;
    default:
      break;
  }
}