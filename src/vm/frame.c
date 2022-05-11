#include "vm/page.h"
#include "vm/swap.h"
#include "vm/frame.h"
#include <list.h>
#include <stdio.h>
#include "threads/thread.h"
#include "threads/synch.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "userprog/syscall.h"
#include "userprog/pagedir.h"
#include "filesys/file.h"

static struct list lru_list;
static struct lock lru_list_lock;
static struct list_elem *lru_clock;

void
lru_list_init (void)
{

  list_init (&lru_list);
  lock_init (&lru_list_lock);
  lru_clock = NULL;
}

void
add_page_to_lru_list (struct page *page)
{

  lock_acquire (&lru_list_lock);
  list_push_back (&lru_list, &page->lru);
  lock_release (&lru_list_lock);
}

void
del_page_from_lru_list (struct page *page)
{

  if (lru_clock == &page->lru)
    lru_clock = list_next (lru_clock);
  list_remove (&page->lru);
}

struct page *
alloc_page (enum palloc_flags flags)
{

  struct page *page;
  page = malloc (sizeof (struct page));
  if (page == NULL)
    return NULL;

  page->kaddr = palloc_get_page (flags);

  while (page->kaddr == NULL)
    {
      try_to_free_pages ();
      page->kaddr = palloc_get_page (flags);
    }
  page->thread = thread_current ();
  add_page_to_lru_list (page);
  return page;
}

void
free_page (void *kaddr)
{

  lock_acquire (&lru_list_lock);
  struct list_elem *e;
  struct page *p;
  for (e = list_begin (&lru_list); e != list_end (&lru_list); e = list_next (e))
    {
      p = list_entry (e, struct page, lru);
      if (p->kaddr == kaddr)
        {
          __free_page (p);
          break;
        }
    }
  lock_release (&lru_list_lock);
}

void
__free_page (struct page *page)
{

  del_page_from_lru_list (page);
  pagedir_clear_page (page->thread->pagedir, page->vme->vaddr);
  palloc_free_page (page->kaddr);
  free (page);
}

static struct list_elem *
get_next_lru_clock (void)
{
  if (list_empty(&lru_list))
    return NULL;

  if (lru_clock == NULL || lru_clock == list_end (&lru_list))
    lru_clock = list_begin (&lru_list);

  lru_clock = list_next (lru_clock);

  if (lru_clock == list_end (&lru_list))
    return get_next_lru_clock ();
  return lru_clock;
}

void
try_to_free_pages (void)
{

  lock_acquire (&lru_list_lock);
  struct page *p;

  p = list_entry (get_next_lru_clock (), struct page, lru);
  while (pagedir_is_accessed (p->thread->pagedir, p->vme->vaddr) || p->vme->pinned)
    {
      pagedir_set_accessed (p->thread->pagedir, p->vme->vaddr, false);
      p = list_entry (get_next_lru_clock (), struct page, lru);
    }

  switch (p->vme->type)
    {
      case VM_BIN:
        if (pagedir_is_dirty (p->thread->pagedir, p->vme->vaddr))
          {
            p->vme->swap_slot = swap_out (p->kaddr);
            p->vme->type = VM_ANON;
          }
        break;
      case VM_FILE:
        if (pagedir_is_dirty (p->thread->pagedir, p->vme->vaddr))
          {
            lock_acquire (&filesys_lock);
            file_write_at (p->vme->file, p->kaddr, p->vme->read_bytes, p->vme->offset);
            lock_release (&filesys_lock);
          }
        break;
      case VM_ANON:
        p->vme->swap_slot = swap_out (p->kaddr);
        break;
    }

  p->vme->is_loaded = false;
  __free_page (p);
  lock_release (&lru_list_lock);
}
