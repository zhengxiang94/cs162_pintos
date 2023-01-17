#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "filesys/filesys.h"
#include <stdint.h>

// At most 8MB can be allocated to the stack
// These defines will be used in Project 2: Multithreading
#define MAX_STACK_PAGES (1 << 11)
#define MAX_THREADS 127

/* PIDs and TIDs are the same type. PID should be
   the TID of the main thread of the process */
typedef tid_t pid_t;

/* Thread functions (Project 2: Multithreading) */
typedef void (*pthread_fun)(void*);
typedef void (*stub_fun)(pthread_fun, void*);

/* The process control block for a given process. Since
   there can be multiple threads per process, we need a separate
   PCB from the TCB. All TCBs in a process will have a pointer
   to the PCB, and the PCB will have a pointer to the main thread
   of the process, which is `special`. */
struct process {
  /* Owned by process.c. */
  uint32_t* pagedir;               /* Page directory. */
  char process_name[16];           /* Name of the main thread */
  struct thread* main_thread;      /* Pointer to main thread */
  struct file* file;               /* Load process file */
  int next_fd;                     /* The fd of the next time the file is opened */
  struct list all_files_list;      /* files list */
  struct lock file_list_lock;      /* files list lock */
  struct list all_threads;         /* all threads in pcb */
  struct semaphore semaph;         /* for pthread_exit_main */
  struct list user_lock_list;      /* user lock list */
  int next_lock_id;                /* next_lock_id for  user lock list */
  struct list user_semaphore_list; /* user semaphore list */
  int next_semaphore_id;           /* next_semaphore_id for user semaphore list */
};

void userprog_init(void);

pid_t process_execute(const char* file_name);
int process_wait(pid_t);
void process_exit(void);
void process_activate(void);

bool is_main_thread(struct thread*, struct process*);
pid_t get_pid(struct process*);

tid_t pthread_execute(stub_fun, pthread_fun, void*);
tid_t pthread_join(tid_t);
void pthread_exit(void);
void pthread_exit_main(void);

bool syscall_lock_init(char* lock);
bool syscall_lock_acquire(char* lock);
bool syscall_lock_release(char* lock);
bool syscall_sema_init(char* sema, int val);
bool syscall_sema_down(char* sema);
bool syscall_sema_up(char* sema);

int get_file_fd(struct file* file);
struct file* get_file(int fd);
bool close_file(int fd);
int read_for_syscall(int fd, void* buffer, unsigned size);
int open_for_syscall(const char* file);
int write_for_syscall(int fd, const void* buffer, unsigned size);
void set_ret_status(struct thread* t, int status);

#endif /* userprog/process.h */
