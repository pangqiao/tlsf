/******************************************************************************
 *
 * INCLUDES
 *
 *****************************************************************************/
#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "tlsf.h"

/******************************************************************************
 *
 * TYPE DEFINES
 *
 *****************************************************************************/

/* match the structure of block_header_t */

#define HEADER_MAGIC_SIZE       (sizeof(int))		/*int header_magic;*/
#define TAIL_MAGIC_SIZE         HEADER_MAGIC_SIZE
#define BLOCK_SIZE              HEADER_MAGIC_SIZE	/*int block_size;*/
#define PAYLOAD_SIZE            HEADER_MAGIC_SIZE

#define HEADER_MAGIC            0x44332211
#define TAIL_MAGIC              0x11223344

#define HEADER_SIZE                  (HEADER_MAGIC_SIZE + BLOCK_SIZE + PAYLOAD_SIZE)
#define TAIL_SIZE                    (TAIL_MAGIC_SIZE + BLOCK_SIZE)

#define MIN_PAYLOAD_SIZE(st)         (2 * sizeof(st *))		/* sizeof(next) + sizeof(prev) */
#define MIN_BLOCK_SIZE(st)           (HEADER_SIZE + MIN_PAYLOAD_SIZE(st) + TAIL_SIZE)

#define TLSF_HEADER_CHECK_SUM(size, blk_size) (HEADER_MAGIC + (size) + (blk_size))

#define LIST1_INDEX_START            5
#define LIST2_INDEX_COUNT_LOG2       5
#define FREE_BIT                     0

#define ALIGNEMENT                   4
#define ALIGNEMENT_MSK               (~(ALIGNEMENT-1))
#define PADD_BYTES                   (ALIGNEMENT - 1)

#ifndef TRUE
#define TRUE    1
#endif

#ifndef FALSE
#define FALSE   0
#endif

#ifndef NULL
#ifdef   __cplusplus
#define  NULL                 0
#else
#define  NULL                 ((void *)0)		/*!< NULL pointer */
#endif
#endif

#if !defined (tlsf_assert)
#define tlsf_assert assert
#endif

#if defined(__cplusplus)
#define	__inline	inline		/* convert to C++ keyword */
#else
#if !defined(__GNUC__) && !defined(__lint__)
#define	__inline				/* delete GCC keyword */
#endif /* !__GNUC__ && !__lint__ */
#endif /* !__cplusplus */

#define TLSF_OBTAIN_LOCK()   do{}while(0)
#define TLSF_RELEASE_LOCK()  do{}while(0)

/* 
 * Use some space marked as used, just in case the first block to merge
 * previous block and the last block to merge the next block.
 */
#define FILL_LEN	8
static U8 fill_head[FILL_LEN]={0x7F, 0xFF, 0xFF, 0xFE, 0x7F, 0xFF, 0xFF, 0xFE};
static U8 fill_tail[FILL_LEN]={0x7F, 0xFF, 0xFF, 0xFE, 0x7F, 0xFF, 0xFF, 0xFE};

/* extern char pool[MAX_HEAP_SIZE]; */
/* extern tlsf_heap_handler_t *instance; */

/* 0x80000003->0x80000004 */
#define ALIGNED_ADDR_WITHHEADER(addr, align)	((addr + align - 1) & (~(align-1)))
/* 0x80000004-0x80000003 -is 1 */
#define ALIGNED_ADDR_OFFSET(addr, align)		(ALIGNED_ADDR_WITHHEADER(addr, align) - addr)

U32 static get_request_size(U32 size)
{
	U32 min_block_size = MIN_BLOCK_SIZE(block_header_t);
	U32 min_payload_size = MIN_PAYLOAD_SIZE(block_header_t);
	int req_size = 0;
	
	if (size < min_payload_size) {
		req_size = min_block_size;
	}else{
		req_size = (size + HEADER_SIZE + TAIL_SIZE + PADD_BYTES ) & ALIGNEMENT_MSK;
	}
	return req_size;
}

static void set_bit(U32 bit, U32 *value)
{
	(*value) |= (1 << bit);
}

static void clear_bit(U32 bit, U32 *value)
{
	(*value) &= (~(1 << bit));
}

static __inline BOOL bit_is_set(U32 bit, U32 value)
{
	return (value & (1 << bit)) != 0 ? TRUE:FALSE;
}

/*
 * This function is used for finding the most significant bit set.
 * for 4116, the msb is 13:  (0b1 0000 0001 0100)
 */
static U32 tlsf_fls_generic(U32 value)
{
	int bit = 32;

	if (!value) return 0;	
	
	if (!(value & 0xffff0000u)) { value <<= 16; bit -= 16; }
	if (!(value & 0xff000000u)) { value <<= 8; bit -= 8; }
	if (!(value & 0xf0000000u)) { value <<= 4; bit -= 4; }
	if (!(value & 0xc0000000u)) { value <<= 2; bit -= 2; }
	if (!(value & 0x80000000u)) { value <<= 1; bit -= 1; }
	
	return bit;
}

/* This function is used to finding the least significant bit set. */
static U32 find_lsb_set(U32 value)
{
	return tlsf_fls_generic(value & -value);
}

static U32 find_msb_set(U32 value)
{
	return tlsf_fls_generic(value);
}

/* 
 * remove the block from the free list directly! the removed blocks should be
 * merged to bigger one when free.
 */
static void remove_from_freelist(tlsf_freelist_t *free_list_t, 
		   block_header_t *block,
		   U32 fl_idx, 
		   U32 sl_idx)
{
	if((block->next == NULL) && (block->prev == NULL)){
		free_list_t->block_table[fl_idx][sl_idx] = NULL;
		clear_bit(sl_idx, &free_list_t->sl_bitmap[fl_idx]);

		/* Clear the list1 bitmap if list2 is empty */
		if(0 == free_list_t->sl_bitmap[fl_idx]){
			clear_bit(fl_idx,&free_list_t->fl_bitmap);	
		}
	} else if (block->prev == NULL){
		/* To make sure if the blk is in sequence */
		if (block->next->prev !=  block){
			return;
		}

	free_list_t->block_table[fl_idx][sl_idx] = block->next;
		   block->next->prev = NULL;
	}
	else if(block->next == NULL){
		block->prev->next = NULL;
	} else {
		/* if there is corruption in the linkedlist */
		if ((block->prev->next != block) || (block->next->prev != block)){
			return;
		}

		block->prev->next = block->next;
		block->next->prev = block->prev;
	}
}

static void find_insert_index(U32 size, U32 *p_fl, U32 *p_sl)
{
	register U32 fl_idx;

	if((fl_idx = find_msb_set(size)) != 0){
		fl_idx -= 1;
		*p_sl = (size ^ (1<<fl_idx)) >> (fl_idx - LIST2_INDEX_COUNT_LOG2);
		*p_fl = fl_idx - LIST1_INDEX_START;
	}
}

/* This function will be used in alloc function to get the
 * right Level1 index and Level2 index
 */
static void find_alloc_index(U32 size,U32 *p_fl,U32 *p_sl)
{
	register U32 fl_idx = find_msb_set(size) - 1;

	const U32 round = (1 << (fl_idx - LIST2_INDEX_COUNT_LOG2)) - 1;
	size += round;
	find_insert_index(size, p_fl, p_sl);
}

static size_t get_block_size(const block_header_t* block)
{
	return block->block_size & ALIGNEMENT_MSK;
}

static void block_prepare_used(block_header_t *block, U32 size)
{
	/* Fill the allocated block structure */
	block->payload_size = size;
	*(U32 *)((char *)block + block->block_size - TAIL_SIZE) = TAIL_MAGIC;

	set_bit(FREE_BIT, (U32 *)((char *)block + block->block_size - 4)); //-TAIL_SIZE+4
	set_bit(FREE_BIT, (U32 *)&block->block_size);

	block->header_magic = TLSF_HEADER_CHECK_SUM(size, block->block_size);

	/* if the payload size is less than the block size, use some padding
	 * there so that can be marked properly to detect errors
	 */ 
	if (get_block_size(block) > (size + HEADER_SIZE + TAIL_SIZE)){
		*((char *)block + HEADER_SIZE + size) = \
		(TAIL_MAGIC & 0xFF);
	}
}

static void set_block_free(block_header_t *block, U32 ins_size)
{
	/* fill the informatino to the free block */
	block->payload_size = 0;  
	block->block_size = ins_size;
	block->header_magic = TLSF_HEADER_CHECK_SUM(block->payload_size, ins_size);
	*(U32 *)((char *)block + ins_size - TAIL_SIZE) = TAIL_MAGIC;
	*(U32 *)((char *)block + ins_size - 4) = ins_size;
}

static block_header_t* search_suitable_block(tlsf_heap_handler_t * handle, 		
		   U32 *p_fl,
		   U32 *p_sl)
{
	U32 fl = *p_fl;
	U32 sl = *p_sl;

	tlsf_freelist_t *free_list_t = &handle->freelist_t;
	U32 sl_map = free_list_t->sl_bitmap[fl] & (~0U << sl);

	if (!sl_map){
		/* No block exists. Search in the next largest first-level list. */
		const U32 fl_map = free_list_t->fl_bitmap & (~0U << (fl + 1));
		if (!fl_map){
			/* No free blocks available, memory has been exhausted. */
			return NULL;
		}

		fl = find_lsb_set(fl_map) - 1;
		*p_fl = fl;
		sl_map = free_list_t->sl_bitmap[fl];
	}

	tlsf_assert(sl_map && "internal error - second level bitmap is null");
	sl = find_lsb_set(sl_map) - 1;
	*p_sl = sl;

	/* Return the first block in the free list. */
	return free_list_t->block_table[fl][sl];
}

/* This function is used for inserting block to linklist. */
static __inline void insert_block(tlsf_freelist_t *free_list_t,
		   block_header_t *block,
		   U32 fl, U32 sl)
{
	block->prev = NULL;
	block->next = free_list_t->block_table[fl][sl];
	free_list_t->block_table[fl][sl] = block;
	if(NULL != block->next){
		block->next->prev = block;
	} else {
		set_bit(fl, &free_list_t->fl_bitmap);
		set_bit(sl, &free_list_t->sl_bitmap[fl]);
	}
}

static void tlsf_remove_blk(tlsf_heap_handler_t *handle, block_header_t* block,
		   U32 fl, U32 sl)
{
	tlsf_freelist_t *free_list_t = &handle->freelist_t;

	if (free_list_t->block_table[fl][sl] == block){
		free_list_t->block_table[fl][sl] = block->next;
		if (NULL == block->next){
			clear_bit(sl, &free_list_t->sl_bitmap[fl]);
			if (0 == free_list_t->sl_bitmap[fl]){
				clear_bit(fl, &free_list_t->fl_bitmap);
			}
		} else {
			block->next->prev = NULL;
		}
	}
}

static void tlsf_insert_blk(tlsf_heap_handler_t *handle, block_header_t* block,
		   U32 block_size)
{
	U32 fl = 0;
	U32 sl = 0;
	tlsf_heap_handler_t *tlsf_handle = (tlsf_heap_handler_t *)handle;

	set_block_free(block, block_size);
	find_insert_index(block_size, &fl, &sl);
	insert_block(&tlsf_handle->freelist_t, block, fl, sl);
}

static block_header_t* get_free_block(tlsf_heap_handler_t * handle, U32 size)
{
	int fl = 0;
	int sl = 0;
	block_header_t* block = NULL;

	if (size){
		find_alloc_index(size, &fl, &sl);
		
		/* 
		 * Note that we don't need to check sl, since it comes from a modulo
		 * operation that guarantees it's always in range.
		 */
		if (fl < MAX_FIRST_LIST)
			block = search_suitable_block(handle, &fl, &sl);
	}

	if (block){
		tlsf_assert(block->block_size >= size);
		tlsf_remove_blk(handle, block, fl, sl);
	}

	return block;
}

static int block_can_split(block_header_t* block, U32 size)
{
	return (get_block_size(block) - size) >= MIN_BLOCK_SIZE(block_header_t);
}

static block_header_t* block_split(tlsf_heap_handler_t *tlsf_handle, 
		block_header_t * block, U32 req_size)
{
	U32 fl = 0;
	U32 sl = 0;
	int size = block->block_size;
	int insert_size = size - req_size;
	block_header_t *remaining_block = (block_header_t *)((char *)block + req_size);

	find_insert_index(insert_size, &fl, &sl);
	set_block_free(remaining_block, insert_size);
	insert_block(&tlsf_handle->freelist_t, remaining_block, fl, sl);

	/* Update the block size due to split */
	block->block_size = req_size;

	*(U32 *)((char *)block + block->block_size - 4) = block->block_size;
}

/* Absorb a free block's storage into an adjacent previous free block. */
static block_header_t* block_merge_prev(void *handle, block_header_t* block)
{
	U32 fl = 0;
	U32 sl = 0;
	U32 prev_size = *(U32*)((char*)block - 4);
	tlsf_heap_handler_t *tlsf_handle = (tlsf_heap_handler_t*)handle;
	block_header_t *prev_block = (block_header_t *)((char *)block - prev_size);

	find_insert_index(prev_size ,&fl, &sl);

	remove_from_freelist(&tlsf_handle->freelist_t, prev_block, fl, sl);
	prev_block->block_size += block->block_size;

	return prev_block;
}

/* Absorb a free block's storage into an adjacent previous free block. */
static block_header_t* block_merge_next(void *handle, block_header_t* block)
{
	U32 fl = 0;
	U32 sl = 0;
	tlsf_heap_handler_t *tlsf_handle = (tlsf_heap_handler_t*)handle;
	block_header_t *next_block = (block_header_t *)((char *)block + get_block_size(block));
	U32 next_size = next_block->block_size;

	find_insert_index(next_size, &fl, &sl);

	remove_from_freelist(&tlsf_handle->freelist_t, next_block, fl, sl);
	block->block_size += next_size;

	return block;
}

static void block_merge_to_prev(void *free_block, U32 front_size)
{
	block_header_t *prev_block = NULL;
	block_header_t *temp_block = (block_header_t *) ((char *)free_block + front_size);
	U32 merge_size = front_size + *(U32*)((char *)free_block - 4);
	
	*(U32*)((char*)temp_block - 4) = merge_size;
	*(U32*)((char*)temp_block - TAIL_SIZE) = TAIL_MAGIC;

	prev_block = (block_header_t *)((char*)temp_block - (merge_size & ALIGNEMENT_MSK));
	prev_block->block_size = merge_size;

	prev_block->header_magic = TLSF_HEADER_CHECK_SUM(prev_block->payload_size,
		prev_block->block_size);
}

static block_header_t *ptr_to_block(void *ptr)
{
	block_header_t *block = (block_header_t *)((char *)ptr - offsetof(block_header_t, next));
	return block;
}

static BOOL block_is_prev_free(block_header_t * block)
{
	BOOL ret = FALSE;
	if (!bit_is_set(FREE_BIT,*(U32 *)((char *)block - 4))){
		ret =  TRUE;
	}

	return ret;
}

static BOOL block_is_next_free(block_header_t * block)
{
	BOOL ret = FALSE;
	if(!bit_is_set(FREE_BIT,*(U32 *)((char *)block + get_block_size(block) + 4))){
		ret =  TRUE;
	}

	return ret;
}

static BOOL block_is_in_range(void *handle, void *mem_ptr)
{
	BOOL ret = FALSE;
	tlsf_heap_handler_t *tlsf_handle = (tlsf_heap_handler_t*)handle;
	if ((U32)tlsf_handle->heap_start < (U32)mem_ptr){
		ret = TRUE;
	}

	return ret;
}

void *tlsf_init_pool(void *pool_start, U32 size)
{
	U32 fl = 0;
	U32 sl = 0;
	U32 ins_size = 0;
	block_header_t *remaining_block = NULL;

	char *mem_start = (char *)pool_start;
	tlsf_heap_handler_t * handle = (tlsf_heap_handler_t *)mem_start;

	memset(mem_start, 0x00, sizeof(tlsf_heap_handler_t));
	mem_start = mem_start + sizeof(tlsf_heap_handler_t);
	size = size - sizeof(tlsf_heap_handler_t);

	memcpy((char *)mem_start, fill_head, sizeof(fill_head));
	mem_start = mem_start + sizeof(fill_head);
	size = size - sizeof(fill_head);

	memcpy(((char *)mem_start + size - sizeof(fill_tail)) , fill_tail, sizeof(fill_tail));
	size = size - sizeof(fill_tail);

	handle->heap_start =  (char *)mem_start;
	handle->heap_end = (char *)mem_start + size;
	handle->heap_size = size;

	remaining_block = (block_header_t*)(void *)(mem_start);
	ins_size =  size;

	set_block_free(remaining_block, ins_size);
	find_insert_index(ins_size, &fl, &sl);

	TLSF_OBTAIN_LOCK();
	insert_block(&handle->freelist_t, remaining_block, fl, sl);
	TLSF_RELEASE_LOCK();

	return handle;
}

/* TODO: ** If we requested 0 bytes, return null, as malloc(0) does. */
void *tlsf_alloc(void *handle, U32 size)
{
	U32 fl = 0;
	U32 sl = 0;
	int req_size = 0;

	block_header_t *block = NULL;
	tlsf_heap_handler_t *tlsf_handle = (tlsf_heap_handler_t *)handle;

	/* Critical section start. */
	TLSF_OBTAIN_LOCK();

	/* 
	 * Get the alloc request size. min payload size is necessary,
	 * because there need the space for prev and next in the free
	 * block.
	 */
	req_size = get_request_size(size);

	if (NULL == (block = get_free_block(handle, req_size))){
		TLSF_RELEASE_LOCK();
		tlsf_assert(block && "internal error - second level bitmap is null");
	}

	if (block_can_split(block, req_size)){
		block_split(handle, block, req_size);
	}

	block_prepare_used(block, size);

	/* Critical section end. */
	TLSF_RELEASE_LOCK();

	return ((block == NULL) ? NULL : (void *)&(block->next));
}

void *tlsf_alloc_aligned(void *handle, U32 size, U32 align)
{
	U32 front_size = 0;
	U32 back_size = 0;
	U32 aligned_size = 0;
	block_header_t *block = NULL;
	block_header_t *free_block = NULL;
	block_header_t *back_block = NULL;
	tlsf_heap_handler_t *tlsf_handle = (tlsf_heap_handler_t*)handle;

	U32 req_size = 0;

	/* Critical section start */
	TLSF_OBTAIN_LOCK();

	req_size = get_request_size(size);
	req_size += align;

	if(NULL == (free_block = get_free_block(handle, req_size))){
		TLSF_RELEASE_LOCK();
		tlsf_assert(free_block && "internal error - second level bitmap is null");
	}

	aligned_size = get_request_size(size);
	front_size = ALIGNED_ADDR_OFFSET((U32)free_block, align);
	back_size = free_block->block_size - aligned_size - front_size;

	block = (block_header_t*)((char *)free_block + front_size);

	if(front_size >= MIN_BLOCK_SIZE(block_header_t)){
		tlsf_insert_blk(handle, free_block, front_size);
	}else if (front_size != 0){
		/* 
		 * the prevoius block must be allocated, if the front_size too small to
		 * insert into the free list block, it should be merged to previous block. 
		 */
		if (block_is_in_range(handle, (void *)((char *)free_block - 4))){
			block_merge_to_prev(free_block, front_size);
		}
	}

	if (back_size >= MIN_BLOCK_SIZE(block_header_t)){
		back_block = (block_header_t *)((char *)block + aligned_size);
		tlsf_insert_blk(handle, back_block, back_size);

		block->block_size = aligned_size;
	}else if(back_size != 0){
		block->block_size = (back_size + aligned_size);
	}

	*(U32*)((char *)block + block->block_size - 4) = block->block_size;

	block_prepare_used(block, size);

	TLSF_RELEASE_LOCK();
	return ((block == NULL) ? NULL : (void *)&(block->next));
}

void tlsf_free(void *handle, void *mem_ptr)
{
	U32 block_size = 0;
	block_header_t *block = ptr_to_block(mem_ptr);
	tlsf_heap_handler_t *tlsf_handle = (tlsf_heap_handler_t*)handle;

	/* Critical section start. */
	TLSF_OBTAIN_LOCK();

	/* Check possible merge with previous. */
	if (block_is_prev_free(block)){
		block = block_merge_prev(tlsf_handle, block);
	}

	/* Check possible merge with next. */
	if (block_is_next_free(block)){
		block = block_merge_next(tlsf_handle, block);
	}

	block_size = get_block_size(block);
	tlsf_insert_blk(tlsf_handle, block, block_size);

	/* Critical section end. */
	TLSF_RELEASE_LOCK();
}
