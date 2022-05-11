#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "userprog/process.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "devices/input.h"
#include "filesys/file.h"
#include <devices/shutdown.h>
#include <filesys/filesys.h>

void syscall_init (void);
struct lock filesys_lock;

#endif /* userprog/syscall.h */
