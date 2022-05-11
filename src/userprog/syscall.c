#include "userprog/syscall.h"
#include "userprog/process.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "devices/input.h"
#include "filesys/file.h"
#include <string.h>
#include "vm/page.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "threads/palloc.h"
#include "threads/malloc.h"

static void syscall_handler (struct intr_frame *);
struct vm_entry *check_address(void *addr, void *esp);
void check_valid_buffer(void *buffer, unsigned size, void *esp, bool to_write);
void check_valid_string(const void *str, void *esp);
void get_argument(void *esp, int *arg, int count);
void halt(void);
void exit(int status);
bool create(const char *file, unsigned initial_size);
bool remove(const char *file);
tid_t exec (const char *cmd_line);
int wait (tid_t tid);
int open (const char *file);
int filesize(int fd);
int read (int fd, void *buffer, unsigned size);
int write (int fd, void *buffer, unsigned size);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);
void sigaction (int signum, void (*handler));
void sendsig (int pid, int signum);
int mmap (int fd, void *addr);
void munmap (int mapid);
void do_munmap(struct mmap_file *mmap_file);
void unpin(void *addr);
void unpin_string(void *str);
void unpin_buffer(void *buffer, unsigned size);


void
syscall_init (void) 
{
  lock_init(&filesys_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
  int arg[3];
  check_address((void *)f->esp,(void *)f->esp);
  int syscall_number = *(int *)f->esp;
  switch (syscall_number)
  {
    case SYS_HALT:
      halt();
      break;

    case SYS_EXIT:
      get_argument(f->esp,arg,1);
      exit(arg[0]);
      break;

    case SYS_CREATE:
      get_argument(f->esp,arg,2);
      check_valid_string((void *)arg[0],f->esp);
      f->eax = create((const char *)arg[0],arg[1]);
      break;

    case SYS_REMOVE:
      get_argument(f->esp,arg,1);
      check_valid_string((void *)arg[0],f->esp);
      f->eax = remove((const char *)arg[0]);
      break;

    case SYS_EXEC:
      get_argument(f->esp, arg, 1);
      check_valid_string((void *)arg[0],f->esp);
      f->eax = exec ((const char *)arg[0]);
      break;

    case SYS_WAIT:
      get_argument(f->esp, arg, 1);
      f->eax = wait((tid_t)arg[0]);
      break;			

    case SYS_OPEN:
      get_argument(f->esp,arg,1);
      check_valid_string((void *)arg[0],f->esp);
      f->eax = open((const char *)arg[0]);
      break;

    case SYS_FILESIZE:	
      get_argument(f->esp,arg,1);
      f->eax = filesize((int)arg[0]);
      break;
			
    case SYS_READ:
      get_argument(f->esp,arg,3);
      check_valid_buffer((void *)arg[1], (unsigned)arg[2], f->esp, true);
      pin_buffer ((void *)arg[1],(unsigned)arg[2],f->esp);
      f->eax = read((int)arg[0],(void *)arg[1],(unsigned)arg[2]);
      break;
			
    case SYS_WRITE:
      get_argument(f->esp,arg,3);
      check_valid_buffer((void *)arg[1], (unsigned)arg[2], f->esp, false);
      f->eax = write((int)arg[0],(void *)arg[1],(unsigned)arg[2]);
      break;

    case SYS_SEEK:
      get_argument(f->esp,arg,2);
      seek((int)arg[0],(unsigned)arg[1]);
      break;

    case SYS_TELL:
      get_argument(f->esp,arg,1);
      f->eax = tell((int)arg[0]);
      break;

    case SYS_CLOSE:
      get_argument(f->esp,arg,1);
      close((int)arg[0]);
      break;

    case SYS_SIGACTION:
      get_argument(f->esp, arg, 2);
      check_valid_string((void *)arg[1],f->esp);
      sigaction((int)arg[0], (void *)arg[1]);
      break;

    case SYS_SENDSIG:
      get_argument(f->esp, arg, 2);
      sendsig((int)arg[0], (int)arg[1]);
      break;

    case SYS_YIELD:
      thread_yield();
      break;

    case SYS_MMAP:
      get_argument(f->esp, arg, 2);
      f->eax = mmap ((int)arg[0], (void *)arg[1]);
      break;

    case SYS_MUNMAP:
      get_argument(f->esp, arg, 1);
      munmap((int)arg[0]);
      break;

    default:
      thread_exit();
      break;
  }	
  unpin (f->esp);
}

struct vm_entry *check_address(void *addr, void *esp UNUSED)
{
  if((unsigned)addr >= 0xc0000000 || (unsigned)addr <= 0x8048000)
    exit(-1);
    
  return find_vme (addr);
}

void
check_valid_buffer (void *buffer, unsigned size, void *esp, bool to_write)
{
  int i;
  struct vm_entry *vme;
  /* Check buffer's address is valid or not.
     It's range is BUFFER to BUFFER+SIZE. */
  for (i = 0; i < size; i++)
    {
      vme = check_address ((char *)buffer + i, esp);
      if (vme && to_write)
        {
          if (vme->writable == false)
            exit (-1);
        }
    }
}

void
check_valid_string (const void *str, void *esp)
{
  char *strs = (char *)str;
  while (*strs)
  {
    if (check_address ((void*)strs, esp) == NULL)
      exit (-1);
    strs++;
  }
}  


void get_argument(void *esp, int *arg, int count)
{
  int i;
  for(i=0;i<count;i++)
    {
      check_address((void *)esp+4+4*i,(void *)esp+4+4*i);
      arg[i] = *(int *)(esp+4+4*i);	
    }
}

void halt(void)
{
  shutdown_power_off();
}

void exit(int status)
{
  struct thread *cur = thread_current();
  cur->exit_status = status;
  printf("%s: exit(%d)\n",cur->name,status);
  thread_exit();
}

bool create(const char *file, unsigned initial_size)
{
  unpin_string (file);
  if (file == NULL)
    return false;
  return filesys_create(file,initial_size);
}

bool remove(const char *file)
{
  return filesys_remove(file);
}
tid_t exec (const char *cmd_line)
{
  int tid;
  struct thread *cp;
  tid = process_execute (cmd_line);
  cp = get_child_process (tid);
  sema_down (&cp->load_sema);
  
  unpin_string(cmd_line);
  if(cp == NULL)
    return -1;

  if (cp->is_load == false)
    return -1;
  else
    return tid;
}

int wait (tid_t tid)
{
  return process_wait (tid);
}

int open(const char *file)
{
  if(file == NULL)
    {
      unpin_string(file);
      return -1;
    }
  lock_acquire (&filesys_lock);
  struct file *f = filesys_open(file);
  if(f==NULL)
    {
      lock_release (&filesys_lock);
      unpin_string(file);
      return -1;
   }
  if(strcmp(file,thread_current()->name)==0)
    file_deny_write(f);
  int fd=process_add_file(f);
  lock_release(&filesys_lock);
  unpin_string(file);
  if(fd > 63)
    return -1;
  return fd;
}

int filesize(int fd)
{
  struct file *f = process_get_file(fd);
  if(f == NULL)
    return -1;
  return file_length(f);
}

int read(int fd, void *buffer,unsigned size)
{
  lock_acquire(&filesys_lock);
  struct file *f = process_get_file(fd);
  if(fd==0)
    {
      *(uint8_t *)buffer = input_getc();
      lock_release(&filesys_lock);
      unpin_buffer(buffer, size);
      return size;
    }
  else
    {
      if(f==NULL)
        {
          lock_release(&filesys_lock);
          unpin_buffer(buffer, size);
          return -1;
        }
      int sizes=file_read(f,buffer,size);
      lock_release(&filesys_lock);
      unpin_buffer(buffer, size);
      return sizes;
    }
}

int write(int fd,void *buffer,unsigned size)
{
  if(fd <= 0)
    {
      unpin_buffer(buffer, size);
      return -1;
    }
  lock_acquire(&filesys_lock);
  struct file *f = process_get_file(fd);
  if(fd == 1)
    {
      putbuf(buffer,size);
      lock_release(&filesys_lock);
      unpin_buffer(buffer, size);
      return size;
    }
  else
    {
      if(f==NULL)
        {
	   lock_release(&filesys_lock);
	   unpin_buffer(buffer, size);
	   return -1;
	}
      int sizes = file_write(f,buffer,size);
      lock_release(&filesys_lock);
      unpin_buffer(buffer, size);
      return sizes;
    }
}

void seek(int fd, unsigned position)
{
  struct file *f = process_get_file(fd);
  if(f==NULL)
    return;
  file_seek(f,position);
}

unsigned tell(int fd)
{
  struct file *f = process_get_file(fd);
  return file_tell(f);
}

void close(int fd)
{
  process_close_file(fd);
}

void sigaction (int signum, void (*handler))
{
  struct thread *cur = thread_current();

  cur->handler[signum - 1] = handler;
}

void sendsig (int pid, int signum)
{
  struct thread *t;
  t = find_tid (pid);

  if (t == NULL)
    return;

  if (t->handler[signum - 1] != NULL)
    printf("Signum: %d, Action: %p\n", signum, t->handler[signum - 1]);
}

int mmap (int fd, void *addr)
{
  struct file *fp;
  fp = process_get_file (fd);

  if (fp==NULL || addr == NULL || (uint32_t) addr % PGSIZE != 0)
    return -1;
    
  if (find_vme (addr) != NULL)
    return -1;
    
  struct mmap_file *mf;
  mf = (struct mmap_file *) malloc (sizeof (struct mmap_file));
  if (mf == NULL)
    return -1;
  

  mf->file = file_reopen(fp);
  if (mf->file == NULL)
    {
      free (mf);
      return -1;
    }
  mf->mapid = thread_current ()->mapid++;
  list_init (&mf->vme_list);

  struct vm_entry *vme;
  size_t read_bytes, zero_bytes;
  int length, offset;
  length = file_length(mf->file);
  offset = 0;

  while (length > 0)
  {
    if (find_vme (addr) != NULL)
      return -1;

    read_bytes = length < PGSIZE ? length : PGSIZE;
    zero_bytes = PGSIZE - read_bytes;

    vme = (struct vm_entry *) malloc (sizeof (struct vm_entry));
    if (vme == NULL)
        return -1;
    vme->type = VM_FILE;
    vme->vaddr = addr;
    vme->writable = true;
    vme->is_loaded = false;
    vme->file = mf->file;
    vme->offset = offset;
    vme->read_bytes = read_bytes;
    vme->zero_bytes = zero_bytes;
    vme->pinned = false;
    
    insert_vme (&thread_current()->vm, vme);
    
    length -= read_bytes;
    offset += read_bytes;
    addr += PGSIZE;
    
    list_push_back (&mf->vme_list, &vme->mmap_elem);
  }

  list_push_back (&thread_current()->mmap_list, &mf->elem);

  return mf->mapid;
}

void munmap (int mapid)
{
  struct mmap_file *mf;
  struct list_elem *e;
  struct thread *t;
  t = thread_current ();
  for (e = list_begin (&t->mmap_list);e != list_end (&t->mmap_list); e = list_next(e))
    {
      mf = list_entry (e, struct mmap_file, elem);
      if (mapid == CLOSE_ALL || mapid == mf->mapid)
        {
          do_munmap (mf);
          file_close (mf->file);
          e = list_prev(list_remove (e));
          free (mf);
        }
    }
}

void do_munmap(struct mmap_file *mmap_file)
{
  struct vm_entry *vme;
  struct list_elem *e;
  struct list *vme_list;
  struct thread *t;
  void *kaddr;
  int size;
  t = thread_current ();
  vme_list = &mmap_file->vme_list;

  for (e = list_begin (vme_list); e != list_end (vme_list); e = list_next(e))
    {
      vme = list_entry (e, struct vm_entry, mmap_elem);
      if (vme->is_loaded)
        {
          kaddr = pagedir_get_page (t->pagedir, vme->vaddr);
          if(pagedir_is_dirty (t->pagedir, vme->vaddr))
            {
              lock_acquire (&filesys_lock);
              file_write_at (vme->file, vme->vaddr, vme->read_bytes, vme->offset);
              lock_release (&filesys_lock);
            }
          pagedir_clear_page(t->pagedir, vme->vaddr);
          free_page (kaddr);
        }
      e = list_prev(list_remove (e));
      delete_vme (&t->vm, vme);
    }
}

void
unpin(void *addr)
{
  /* Set page to unpinning page after syscall. */
  struct vm_entry *vme = find_vme(addr);
  if(vme != NULL)
    {
      vme->pinned =false;
    }
}

void
unpin_string(void *str)
{
  /* For all str to NULL set unpinning page. */
  unpin(str);
  while(*(char *)str !=0)
    {
      str = (char *)str+1;
      unpin(str);
    }
}

void
unpin_buffer(void *buffer, unsigned size)
{
  /* For all BUFFERS to BUFFERS+SIZE set unpinning page. */
  unsigned i;
  char *buffers = (char *)buffer;
  for(i=0;i<size;i++)
    {
      unpin(buffers);
      buffers++;
    }
}

void
pin (void *addr,void *esp)
{
  /* Set page to pinning page when do syscall. */
  struct vm_entry *vme = find_vme (addr);
  if(vme == NULL)
    {
      if(addr >= esp - 32)
        {
          expand_stack(addr);
          vme = find_vme (addr);
        }
    }
  if (vme->writable == false)
    exit (-1);
  vme->pinned = true;
  if (vme->is_loaded == false)
    handle_mm_fault (vme);
}

void
pin_buffer(void *buffer, unsigned size,void *esp)
{
  /* For all BUFFERS to BUFFERS+SIZE set pinning page. */
  unsigned i;
  char *buffers = (char *)buffer;
  for(i=0;i<size;i++)
    {
      pin(buffers,esp);
      buffers++;
    }
}
