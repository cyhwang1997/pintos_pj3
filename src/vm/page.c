#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/palloc.h"
#include "userprog/process.h"
#include "vm/page.h"
#include "vm/swap.h"
#include "devices/block.h"

static unsigned vm_hash_func (const struct hash_elem *e, void *aux UNUSED);
static bool vm_less_func (const struct hash_elem *a, const struct hash_elem *b);
void vm_hash_destroy_func (struct hash_elem *e, void *aux UNUSED);

void
vm_init (struct hash *vm)
{

  hash_init (vm, vm_hash_func, vm_less_func, NULL);
}

static unsigned
vm_hash_func (const struct hash_elem *e, void *aux UNUSED)
{

  struct vm_entry *vme;
  vme = hash_entry (e, struct vm_entry, elem);
  return hash_int ((int)vme->vaddr);
}

static bool
vm_less_func (const struct hash_elem *a, const struct hash_elem *b)
{

  struct vm_entry *va;
  struct vm_entry *vb;
  va = hash_entry (a, struct vm_entry, elem);
  vb = hash_entry (b, struct vm_entry, elem);
  return va->vaddr < vb->vaddr;
}

bool
insert_vme (struct hash *vm, struct vm_entry *vme)
{

  if (hash_insert (vm, &vme->elem) != NULL)
    return false;
  else
    return true;
}

bool
delete_vme (struct hash *vm, struct vm_entry *vme)
{

  void *kaddr;
  if (hash_delete (vm, &vme->elem) != NULL)
    {
      kaddr=pagedir_get_page(thread_current()->pagedir,vme->vaddr);
      free_page(kaddr);
      pagedir_clear_page(thread_current()->pagedir, vme->vaddr);
      free (vme);
      return true;
    }
  else
    return false;
}

struct vm_entry *
find_vme (void *vaddr)
{

  struct vm_entry vme;
  vme.vaddr = pg_round_down (vaddr);
  struct hash_elem *e;
  e = hash_find (&thread_current ()->vm, &vme.elem);
  if (e != NULL)
    return hash_entry (e, struct vm_entry, elem);
  else
    return NULL;
}

void
vm_destroy (struct hash *vm)
{

  hash_destroy (vm, vm_hash_destroy_func);
}

void
vm_hash_destroy_func (struct hash_elem *e, void *aux UNUSED)
{

  struct vm_entry *vme;
  vme = hash_entry (e, struct vm_entry, elem);
  void *kaddr;
  if(vme->is_loaded == true)
    {
      kaddr=pagedir_get_page(thread_current()->pagedir,vme->vaddr);
      free_page(kaddr);
      pagedir_clear_page(thread_current()->pagedir, vme->vaddr);
    }
  free (vme);
}

bool
load_file (void *kaddr, struct vm_entry *vme)
{
  if (file_read_at (vme->file, kaddr, vme->read_bytes, vme->offset) != (int) vme->read_bytes)
    return false;
  memset (kaddr + vme->read_bytes, 0, vme->zero_bytes);
  return true;

}
