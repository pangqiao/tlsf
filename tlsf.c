/****************************************************************************
INCLUDES
****************************************************************************/
#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "tlsf.h"

/****************************************************************************
 * TYPE DEFINES                                                                      *
 ****************************************************************************/
/*match the structure of block_header_t*/ 
#define HEADER_MAGIC_SIZE       (sizeof(int)) 		/*int header_magic;*/
#define TAIL_MAGIC_SIZE         HEADER_MAGIC_SIZE
#define BLOCK_SIZE              HEADER_MAGIC_SIZE 	/*int block_size;*/
#define PAYLOAD_SIZE            HEADER_MAGIC_SIZE

#define HEADER_MAGIC            0x44332211
#define TAIL_MAGIC              0x11223344

#define HEADER_SIZE                  (HEADER_MAGIC_SIZE + BLOCK_SIZE + PAYLOAD_SIZE)
#define TAIL_SIZE                    (TAIL_MAGIC_SIZE + BLOCK_SIZE)

#define MIN_PAYLOAD_SIZE(st)         (2 * sizeof(st *)) /*sizeof(next) + sizeof(prev)*/
#define MIN_BLOCK_SIZE(st)           (HEADER_SIZE + MIN_PAYLOAD_SIZE(st) + TAIL_SIZE)

#define TLSF_HEADER_CHECK_SUM(size, blk_size) (HEADER_MAGIC + (size) + (blk_size))

#define LIST1_INDEX_START            5
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
#define  NULL                 ((void *)0)    /*!< NULL pointer */
#endif
#endif


#if !defined (tlsf_assert)
#define tlsf_assert assert
#endif

#if defined(__cplusplus)
#define	__inline	inline		/* convert to C++ keyword */
#else
#if !defined(__GNUC__) && !defined(__lint__)
#define	__inline			/* delete GCC keyword */
#endif /* !__GNUC__  && !__lint__ */
#endif /* !__cplusplus */

#define TLSF_OBTAIN_LOCK()   do{}while(0)
#define TLSF_RELEASE_LOCK()  do{}while(0)


#define FILL_LEN	8
static U8 fill_head[FILL_LEN]={0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
static U8 fill_tail[FILL_LEN]={0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99};

extern char pool[MAX_HEAP_SIZE];
extern tlsf_heap_handler_t *gp_heap_handle;

/*0x80000003->0x80000004*/
#define ALIGNED_ADDR_WITHHEADER(addr, align) 	((addr + align - 1) & (~(align-1)))   
/*0x80000004-0x80000003 -is 1*/
#define ALIGNED_ADDR_OFFSET(addr, align)  		(ALIGNED_ADDR_WITHHEADER(addr, align) - addr)

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

/* This function is used to finding the least significant bit set.*/
static  U32 find_lsb_set(U32 value)
{
	int ret = 32;

	value = (value & -value);

	if (!value)
		return 0;
	
	if (!(value & 0xffff0000u)) {
		value <<= 16;
		ret -= 16;
	}
	
	if (!(value & 0xff000000u)) {
		value <<= 8;
		ret -= 8;
	}
	
	if (!(value & 0xf0000000u)) {
		value <<= 4;
		ret -= 4;
	}
	
	if (!(value & 0xc0000000u)) {
		value <<= 2;
		ret -= 2;
	}
	
	if (!(value & 0x80000000u)) {
		value <<= 1;
		ret -= 1;
	}

	return ret;
}

/*This function is used for finding the most significant bit set.
for 4116, the msb is 13:  (0b1 0000 0001 0100)*/
static  U32 find_msb_set(U32 value)
{
	int ret = 32;

	if (!value)
		return 0;	
	
	if (!(value & 0xffff0000u)) {
		value <<= 16;
		ret -= 16;
	}
	
	if (!(value & 0xff000000u)) {
		value <<= 8;
		ret -= 8;
	}
	
	if (!(value & 0xf0000000u)) {
		value <<= 4;
		ret -= 4;
	}
	
	if (!(value & 0xc0000000u)) {
		value <<= 2;
		ret -= 2;
	}
	
	if (!(value & 0x80000000u)) {
		value <<= 1;
		ret -= 1;
	}
	
	return ret;
}

static void tlsf_log_error(Tlsf_ErrStruct *ptr, 
		tlsf_ErrCode err_code, 
		void *mem_ptr,
		U32 blk_size)
{
	ptr->err_code = err_code;
	ptr->mem_ptr = mem_ptr;
	ptr->block_size = blk_size;
}

/*remove the block from the free list directly! the removed blocks should be merged
to bigger one when free. */
static void remove_from_freelist(tlsf_freelist_t *free_list_t, 
		block_header_t *block,
		U32 fl_idx, 
		U32 sl_idx, 
		Tlsf_ErrStruct *error)
{
    if((block->next == NULL) && (block->prev == NULL)){
		free_list_t->block_table[fl_idx][sl_idx] = NULL;
		clear_bit(sl_idx, &free_list_t->sl_bitmap[fl_idx]);

		/* Clear the list1 bitmap if list2 is empty */
		if(0 == free_list_t->sl_bitmap[fl_idx]){
			clear_bit(fl_idx,&free_list_t->fl_bitmap);	
		}
    } else if (block->prev == NULL){
		/* To make sure if the blk is in sequence*/
		if (block->next->prev !=  block){
			tlsf_log_error(error, TLSF_DATASTRUCT_CORRUPTED, NULL, 0);
			tlsf_trap(error);
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
			tlsf_log_error(error, TLSF_DATASTRUCT_CORRUPTED, NULL, 0);
			tlsf_trap(error);
			return;
		}

		block->prev->next = block->next;
		block->next->prev = block->prev;
    }
}

/*This function will be used in alloc function to get the right Level1 index and Level2 index */
static void find_alloc_index(U32 req_size,U32 *p_fl,U32 *p_sl)
{
    U32 fl_idx = 0;
    U32 sl_idx = 0;

	if((fl_idx = find_msb_set(req_size)) != 0){
		/* find the initial segregated list indexes. */
		fl_idx -= 1;
		sl_idx = (req_size ^ (1<<fl_idx)) >> (fl_idx - LIST1_INDEX_START);
		fl_idx -= LIST1_INDEX_START;
	} else {
		/*required size is not valide vaue */
		return; 
	}

	if(req_size & ((1 << fl_idx)-1)){
		sl_idx += 1;
		if (sl_idx > 31){
			fl_idx += 1;
			sl_idx = 0;
		}
	}

	*p_fl = fl_idx;
	*p_sl = sl_idx;
}

static void find_insert_index(U32 req_size,U32 *p_fl,U32 *p_sl)
{
	register U32 fl_idx;

	if((fl_idx = find_msb_set(req_size)) != 0){
		fl_idx -= 1;
		*p_sl = (req_size ^ (1<<fl_idx)) >> (fl_idx - LIST1_INDEX_START);
		*p_fl = fl_idx - LIST1_INDEX_START;
	}
}

static void fill_insert_blk(block_header_t *temp_block,U32 ins_size)
{
	/* Free block */
	temp_block->payload_size = 0;  
	temp_block->block_size   = ins_size;
	temp_block->header_magic = TLSF_HEADER_CHECK_SUM(temp_block->payload_size,ins_size);
	*(U32 *)((char *)temp_block + ins_size - TAIL_SIZE) = TAIL_MAGIC;
	*(U32 *)((char *)temp_block + ins_size - 4) = ins_size;
}
/*remove the block acorrding to the index, if no suitable block, will try to get the 
bigger block.*/
static block_header_t *remove_blk(tlsf_heap_handler_t *handle,
		U32 fl_idx,
		U32 sl_idx, 
		Tlsf_ErrStruct *error)
	{
	U32 lst1_msk;
	U32 lst2_msk;
	U32 free_idx2;
	U32 free_idx1;
	block_header_t *block;
	tlsf_freelist_t *free_list_t = &handle->freelist_t;

	lst2_msk = ~((1 << sl_idx) - 1);
	lst1_msk = ~((1<< (fl_idx+1)) -1 );
	free_idx2 = find_lsb_set(free_list_t->sl_bitmap[fl_idx] & lst2_msk);
	if(0 != free_idx2 ){
		block = free_list_t->block_table[fl_idx][free_idx2 - 1];
		free_list_t->block_table[fl_idx][free_idx2 - 1] = block->next;
		if (NULL == block->next){
			clear_bit(free_idx2-1, &free_list_t->sl_bitmap[fl_idx]);
			if (0 == free_list_t->sl_bitmap[fl_idx]){
				clear_bit(fl_idx,&free_list_t->fl_bitmap);
			}
		} else {
			block->next->prev = NULL;
		}
	} else if (0 !=(free_idx1 = find_lsb_set(free_list_t->fl_bitmap & lst1_msk))){
		free_idx2 = find_lsb_set(free_list_t->sl_bitmap[free_idx1-1]);
		block = free_list_t->block_table[free_idx1-1][free_idx2-1];
		free_list_t->block_table[free_idx1-1][free_idx2-1] = block->next;
		if(NULL == block->next){
			clear_bit(free_idx2-1,&free_list_t->sl_bitmap[free_idx1-1]);
			if(0 == free_list_t->sl_bitmap[free_idx1-1]){
				clear_bit(free_idx1-1,&free_list_t->fl_bitmap);
			}
		} else {
			block->next->prev = NULL;
		}
	} else {
		error->err_code = TLSF_NO_MEM;
		block = NULL;
	}
	
	return block;
}


/* This function is used for inserting block to linklist */
static __inline void insert_blk(tlsf_freelist_t *free_list_t,
		block_header_t *p_ins,
		U32 fl_idx, 
		U32 sl_idx)
{
	p_ins->prev = NULL;
	p_ins->next = free_list_t->block_table[fl_idx][sl_idx];
	free_list_t->block_table[fl_idx][sl_idx] = p_ins;
	if(NULL != p_ins->next){
		p_ins->next->prev = p_ins;
	} else {
		set_bit(fl_idx, &free_list_t->fl_bitmap);
		set_bit(sl_idx, &free_list_t->sl_bitmap[fl_idx]);
	}
}

void tlsf_trap(Tlsf_ErrStruct *error)
{
	if (error->err_code == TLSF_NO_MEM){ 
		PRINT_MSG("no memory!\n");
	}
	else { 
		PRINT_MSG("tlsf_trap:error->err_code is %d,  mem_ptr is 0x%X, block_size is %d.\n",
			error->err_code, (U32)error->mem_ptr, error->block_size);
		tlsf_assert(0);
	}
}

void *tlsf_alloc(void *handle, U32 size, Tlsf_ErrStruct *error)
{
	U32 fl_idx = 0;
	U32 sl_idx = 0;
	int req_size = 0;
	U32 ins_size = 0;
	U32 size_chk = (~0);
	U32 min_block_size = MIN_BLOCK_SIZE(block_header_t);
	U32 min_payload_size = MIN_PAYLOAD_SIZE(block_header_t);

	block_header_t *block = NULL,*insert_block = NULL;

	tlsf_heap_handler_t *tlsf_handle = (tlsf_heap_handler_t*)handle;

	/* Critical section start */
	TLSF_OBTAIN_LOCK();
	
	error->err_code = TLSF_SUCCESS;

	/* Get the alloc request size. min payload size is necessary, because there need
	the space for prev and next in the free block.*/
	if (size < min_payload_size) {
		req_size = min_block_size;
	}else{
		req_size = (size + HEADER_SIZE + TAIL_SIZE + PADD_BYTES ) & ALIGNEMENT_MSK;
	}
	
	find_alloc_index(req_size, &fl_idx, &sl_idx);

	if(NULL == (block = remove_blk(tlsf_handle, fl_idx, sl_idx, error))){
		/*error->err_code = TLSF_NO_MEM;*/
		goto alloc_exit;
	}

	ins_size = block->block_size - req_size;
	
	if(ins_size >= min_block_size){
		insert_block = (block_header_t *)((char *)block+req_size);

		find_insert_index(ins_size, &fl_idx, &sl_idx);
		fill_insert_blk(insert_block, ins_size);
		insert_blk(&tlsf_handle->freelist_t, insert_block, fl_idx, sl_idx);

		/* Update the block size due to split */
		block->block_size   = block->block_size - ins_size;
		*(U32 *)((char *)block + block->block_size - 4) = block->block_size;
	}

	/* Fill the allocated block structure */
	block->payload_size = size;
	*(U32 *)((char *)block + block->block_size - TAIL_SIZE) = TAIL_MAGIC;

	tlsf_handle->heap_alloc_size += block->block_size;

	set_bit(FREE_BIT, (U32 *)((char *)block + block->block_size-4)); //-TAIL_SIZE+4
	set_bit(FREE_BIT, (U32 *)&block->block_size);

	block->header_magic = TLSF_HEADER_CHECK_SUM(size,block->block_size);

	/* if the payload size is less than the block size means some padding
	is there so that can be marked properly to detect errors */
	if ((block->block_size & ALIGNEMENT_MSK) > (size + HEADER_SIZE + TAIL_SIZE)){
		*((char *)block + HEADER_SIZE + size) = \
		(TAIL_MAGIC & 0xFF);
	}

alloc_exit:
	if (error->err_code == TLSF_SUCCESS){    
		TLSF_RELEASE_LOCK();
		return ((block == NULL)? NULL:(void *) &(block->next));
	} else if (error->err_code == TLSF_NOT_SUPPORTED){
		tlsf_trap(error);
	} else if (error->err_code == TLSF_NO_MEM){	
		TLSF_RELEASE_LOCK();
		tlsf_trap(error);
	}
	
	return NULL;
}


void *tlsf_init_pool(void *pool_start, U32 size)
{
	U32 fl_idx = 0;
	U32 sl_idx = 0;
	U32 ins_size = 0;
	block_header_t *insert_block = NULL;
	char *mem_temp = 0;

	char *mem_start = (char *)pool_start;
	tlsf_heap_handler_t * handle = (tlsf_heap_handler_t *)mem_start;
	
	memset(mem_start, 0x00, sizeof(tlsf_heap_handler_t));

	mem_start = mem_start + sizeof(tlsf_heap_handler_t);
	memcpy((char *)mem_start, fill_head, sizeof(fill_head));
	
	mem_start = mem_start + sizeof(fill_head);
	size = size - sizeof(tlsf_heap_handler_t) - sizeof(fill_head);

	handle->heap_start =  (char *)mem_start;
	handle->heap_end = (char *)mem_start + size;
	handle->heap_size = size;
	handle->heap_alloc_size = 0;

	insert_block = (block_header_t*)(void *)(mem_start);
	ins_size =  size;

	fill_insert_blk(insert_block,ins_size);
	find_insert_index(ins_size, &fl_idx, &sl_idx);

	TLSF_OBTAIN_LOCK();
	insert_blk(&handle->freelist_t, insert_block, fl_idx, sl_idx);
	TLSF_RELEASE_LOCK();
	
	return handle;
}

void tlsf_free(void *handle,
		void *mem_ptr,
		Tlsf_ErrStruct *error)
{
	block_header_t *p_temp_blk;
	block_header_t *p_back_blk = NULL;
	char *p_front_tail = NULL;
	char *p_blk_tail = NULL;
	tlsf_heap_handler_t *tlsf_handle = (tlsf_heap_handler_t*)handle;
	U32 front_merge_size=0;
	U32 back_merge_size=0;
	U32 merge_size=0;
	U32 cur_blk_size = 0;
	U32 fl_idx;
	U32 sl_idx;

	block_header_t *block = (block_header_t *)((char *)mem_ptr - offsetof(block_header_t, next));
	
	/* Critical section start */
	TLSF_OBTAIN_LOCK();
	error->err_code = TLSF_SUCCESS;

	/* Check possible merge with previous */
	if(!bit_is_set(FREE_BIT,*(U32 *)((char *)block - 4))){
		front_merge_size = *(U32*)((char*)block-4);
		p_temp_blk = (block_header_t *)((char *)block - front_merge_size);
		p_front_tail = ((char *)block - TAIL_SIZE);

		find_insert_index(front_merge_size,&fl_idx,&sl_idx);

		remove_from_freelist(&tlsf_handle->freelist_t,
			p_temp_blk, fl_idx,
			sl_idx, error);
	}

	if(!bit_is_set(FREE_BIT,*(U32 *)((char *)block+(block->block_size & ALIGNEMENT_MSK) + 4))){
		p_temp_blk = (block_header_t *)((char *)block + (block->block_size & ALIGNEMENT_MSK));

		p_back_blk = p_temp_blk;
		back_merge_size = p_temp_blk->block_size;
		find_insert_index(back_merge_size,&fl_idx,&sl_idx);

		remove_from_freelist(&tlsf_handle->freelist_t, p_temp_blk,
			fl_idx, sl_idx, error);
	}

	cur_blk_size = (block->block_size & ALIGNEMENT_MSK);

	merge_size = front_merge_size + back_merge_size + cur_blk_size;
	p_temp_blk = (block_header_t *)((char *)block-front_merge_size);

	fill_insert_blk(p_temp_blk,merge_size);
	find_insert_index(merge_size,&fl_idx,&sl_idx);
	insert_blk(&tlsf_handle->freelist_t,p_temp_blk,fl_idx,sl_idx);

	tlsf_handle->heap_alloc_size -= cur_blk_size;

free_exit:

	TLSF_RELEASE_LOCK();
	if(error->err_code != TLSF_SUCCESS){
		tlsf_trap(error);
	}
}


void *tlsf_alloc_aligned(void *handle, 
		U32 size, 
		U32 align,
		Tlsf_ErrStruct *error)
{

	U32 fl_idx =0;
	U32 sl_idx =0;
	U32 temp_size;
	U32 fnt_size, bak_size, algned_blk_size;
	block_header_t *temp_block = NULL, *block = NULL;
	tlsf_heap_handler_t *tlsf_handle = (tlsf_heap_handler_t*)handle;

	U32 req_size = 0;

	error->err_code = TLSF_SUCCESS;

	/* Critical section start */
	TLSF_OBTAIN_LOCK();

	req_size = get_request_size(size);
	req_size += align;

	find_alloc_index(req_size, &fl_idx, &sl_idx);

	if(NULL == (block = remove_blk(tlsf_handle, fl_idx, sl_idx, error))){
		/*error->err_code = TLSF_NO_MEM;*/
		goto alloc_aligned_exit;
	}

	algned_blk_size = get_request_size(size);
	fnt_size = ALIGNED_ADDR_OFFSET((U32)block, align);
	bak_size = block->block_size - algned_blk_size - fnt_size;

	temp_block = (block_header_t*) ((char *)block + fnt_size);

	if(fnt_size >= MIN_BLOCK_SIZE(block_header_t)){
		find_insert_index(fnt_size, &fl_idx, &sl_idx);
		fill_insert_blk(block, fnt_size);
		insert_blk(&tlsf_handle->freelist_t, block, fl_idx, sl_idx);
	}else if (fnt_size != 0){
		/*the prevoius block must be allocated, if the fnt_size too small to
		insert into the free list block, it should be merged to previous block.*/
		temp_size = fnt_size + *(U32*)((char *)block - 4);
		*(U32*)((char*)temp_block - 4) = temp_size;
		*(U32*)((char*)temp_block - TAIL_SIZE) = TAIL_MAGIC;

		block = (block_header_t *)((char*)temp_block - (temp_size & ALIGNEMENT_MSK));
		block->block_size = temp_size;

		block->header_magic = TLSF_HEADER_CHECK_SUM(block->payload_size, block->block_size);

		tlsf_handle->heap_alloc_size += fnt_size;
	}

	if (bak_size >= MIN_BLOCK_SIZE(block_header_t)){
		block = (block_header_t *)((char *)temp_block + algned_blk_size);

		find_insert_index(bak_size, &fl_idx, &sl_idx);
		fill_insert_blk(block, bak_size);
		insert_blk(&tlsf_handle->freelist_t, block, fl_idx, sl_idx);

		temp_block->block_size = algned_blk_size;
	}else if(bak_size != 0){
		temp_block->block_size =  (bak_size +  algned_blk_size);
	}

	temp_block->payload_size = size;

	*(U32*)((char *)temp_block + temp_block->block_size - 4) =  temp_block->block_size;
	*(U32 *)((char *)temp_block + temp_block->block_size - TAIL_SIZE) = TAIL_MAGIC;

	tlsf_handle->heap_alloc_size += temp_block->block_size;

	/* Set the block as allocated */
	set_bit(FREE_BIT,(U32 *)((char *)temp_block + temp_block->block_size-4));
	set_bit(FREE_BIT,&temp_block->block_size);

	temp_block->header_magic = TLSF_HEADER_CHECK_SUM(size, temp_block->block_size);

	/*advanced tail check.*/
	if((temp_block->block_size & ALIGNEMENT_MSK) > (size + HEADER_SIZE + TAIL_SIZE)){
		*((char *)temp_block + HEADER_SIZE + size ) = \
		(TAIL_MAGIC & 0xFF);
	}

	alloc_aligned_exit:

	if (error->err_code == TLSF_SUCCESS){    
		TLSF_RELEASE_LOCK();
		return ((temp_block == NULL)? NULL:(void *) &(temp_block->next));
	} else if (error->err_code == TLSF_NOT_SUPPORTED){
		tlsf_trap(error);
	} else if (error->err_code == TLSF_NO_MEM){	
		TLSF_RELEASE_LOCK();
		tlsf_trap(error);
	}
}


/****************************************************************************************
* Function   : tlsf_reallocate
* Description:
****************************************************************************************/
void* tlsf_reallocate(void* handle,
		void *mem_ptr,
		U32 size,
		Tlsf_ErrStruct *error)
{
	block_header_t *p_blk = (block_header_t *)((char *)mem_ptr - HEADER_SIZE);
	block_header_t *temp_block = NULL;
	block_header_t *next_block = NULL;
	void *p_ret_mem_ptr = 0;
	U32 req_size = 0,cur_blk_size = 0,ins_size = 0,payload_size = 0;
	U32 fl_idx = 0;
	U32 sl_idx = 0;

	error->err_code = TLSF_SUCCESS;

	tlsf_heap_handler_t *tlsf_handle = (tlsf_heap_handler_t*)handle;

	TLSF_OBTAIN_LOCK();

	/* Get the alloc request size */
	req_size = get_request_size(size);
	cur_blk_size = (p_blk->block_size & ALIGNEMENT_MSK);

	payload_size = p_blk->payload_size;

	if (req_size <= cur_blk_size){
		/*In this case, try to split and merge next free block to new free block*/
		ins_size = cur_blk_size - req_size;
		next_block = (block_header_t *)((char *)p_blk + cur_blk_size);

		/*1.  Need to see the split block can be merged with next block */
		if(!bit_is_set(FREE_BIT, next_block->block_size)){
			/*2. Yes, the next block is free, it need to be merged to a bigger one!*/
			ins_size += next_block->block_size;
			find_insert_index(next_block->block_size, &fl_idx, &sl_idx);

			/*3. remove the next_block from the free list first.*/
			remove_from_freelist(&tlsf_handle->freelist_t,
				next_block,
				fl_idx,
				sl_idx, error);
		}

		/*4. add the splitted (or next free)block to the free list.*/
		if(ins_size >= MIN_BLOCK_SIZE(block_header_t)){
			temp_block = (block_header_t *)((char *)p_blk + req_size);

			find_insert_index(ins_size, &fl_idx, &sl_idx);
			fill_insert_blk(temp_block, ins_size);
			insert_blk(&tlsf_handle->freelist_t, temp_block, fl_idx, sl_idx);

			/* Resize the block size */
			p_blk->block_size = req_size;
			set_bit(FREE_BIT, &p_blk->block_size);
			*(U32*)((char*)p_blk + req_size - TAIL_SIZE) = TAIL_MAGIC;
			*(U32*)((char*)p_blk + req_size - 4) = p_blk->block_size;

			/* this is introduced to send the information */
			tlsf_handle->heap_alloc_size -= (cur_blk_size - req_size);
		}
	}else  {
		next_block = (block_header_t*)((char*) p_blk + cur_blk_size);

		/*Need allocate new memory as the next blk is allocated or next block
		memory is not big enough*/
		if((next_block->block_size & 0x3) ||
		((cur_blk_size + next_block->block_size) < req_size )){
			TLSF_RELEASE_LOCK();/*release it before alloc.*/

			/*or tslf_alloc_aligned*/
			p_ret_mem_ptr = tlsf_alloc(handle, size, error);

			if(p_ret_mem_ptr != NULL){
				memcpy((char*)p_ret_mem_ptr, mem_ptr, payload_size);
				tlsf_free(handle, mem_ptr, error);
			}
		}else{
			/* Remove the blk from free list */
			find_insert_index(next_block->block_size, &fl_idx, &sl_idx);
			remove_from_freelist(&tlsf_handle->freelist_t, next_block,
				fl_idx, sl_idx, error);
			ins_size = cur_blk_size + next_block->block_size - req_size;

			if(ins_size >= MIN_BLOCK_SIZE(block_header_t)){
				/* need to splitt the block */
				next_block = (block_header_t*)((char *)p_blk + req_size);

				find_insert_index(ins_size, &fl_idx, &sl_idx);
				fill_insert_blk(next_block, ins_size);
				insert_blk(&tlsf_handle->freelist_t, next_block, fl_idx, sl_idx);

				/* resize the block */
				p_blk->block_size = req_size;
				set_bit(FREE_BIT, &p_blk->block_size);
				*(U32*)((char*) p_blk + req_size - TAIL_SIZE) = TAIL_MAGIC;
				*(U32*)((char*) p_blk + req_size - 4) = p_blk->block_size;

				/* this is introduced to send the information */
				tlsf_handle->heap_alloc_size += (req_size - cur_blk_size);

			}else{
				/* this is introduced to send the information */
				tlsf_handle->heap_alloc_size += next_block->block_size;
				p_blk->block_size = cur_blk_size + next_block->block_size;
				*(U32*)((char*) p_blk + p_blk->block_size - TAIL_SIZE) = TAIL_MAGIC;
				*(U32*)((char*) p_blk + p_blk->block_size - 4) = p_blk->block_size;
				set_bit(FREE_BIT,(U32*)((char*) p_blk + p_blk->block_size - 4));
				set_bit(FREE_BIT, &p_blk->block_size);
			}
		}
	}

realloc_exit:
	if(error->err_code == TLSF_SUCCESS){
		if(p_ret_mem_ptr == NULL){
			p_blk->payload_size = size;
			p_blk->header_magic = TLSF_HEADER_CHECK_SUM(size, p_blk->block_size);

			if((p_blk->block_size & ALIGNEMENT_MSK) > (size + HEADER_SIZE + TAIL_SIZE)){
				*((char *)p_blk + HEADER_SIZE + size) = \
				(TAIL_MAGIC & 0xFF);
			}
			p_ret_mem_ptr = (void *) &p_blk->next;

			TLSF_RELEASE_LOCK();
		}
	}

	return p_ret_mem_ptr;
}



