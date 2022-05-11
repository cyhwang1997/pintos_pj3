#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <hash.h>
#define VM_BIN 0
#define VM_FILE 1
#define VM_ANON 2

#define CLOSE_ALL 0

struct vm_entry
{
  uint8_t type;
  void *vaddr;
  bool writable;
  bool is_loaded;
  struct file* file;
  
  bool pinned;
  
  /* for mmap */
  struct list_elem mmap_elem;
  
  size_t offset;
  size_t read_bytes;
  size_t zero_bytes;

  /* for swapping */
  size_t swap_slot;

  struct hash_elem elem;  
};

struct mmap_file {
  int mapid;
  struct file* file;
  struct list_elem elem;
  struct list vme_list;
};

struct page
{
  void *kaddr;			
  struct vm_entry *vme;	
  struct thread *thread;	
  struct list_elem lru;		
};

void vm_init(struct hash *vm);

bool insert_vme(struct hash *vm, struct vm_entry *vme);
bool delete_vme (struct hash *vm, struct vm_entry *vme);

void vm_destroy (struct hash *vm);
struct vm_entry *find_vme (void *vaddr);
bool load_file (void *kaddr, struct vm_entry *vme);

#endif /* vm/page.h */
