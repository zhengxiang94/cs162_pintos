#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/process.h"

void syscall_exit(struct intr_frame* f, int status);
void syscall_init(void);

#endif /* userprog/syscall.h */
