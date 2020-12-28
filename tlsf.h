#if !defined (tlsf_h)
#define tlsf_h

#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

typedef unsigned int U32;
typedef int BOOL;
typedef unsigned char U8;

//#define USE_PRINTF
#ifdef USE_PRINTF
#define PRINT_MSG(fmt, args...)  printf(fmt, ##args)
#else
#define PRINT_MSG(fmt, args...)
#endif

#define MB                           (1024*1024)
#define MAX_HEAP_SIZE                8*MB

/****************************************************************************
 * ENUMERATIONS                                                             *
 ****************************************************************************/
typedef enum tlsf_ErrCode{
	TLSF_SUCCESS                   =  0,
	TLSF_NOT_SUPPORTED             =  1,
	TLSF_NO_MEM                    =  2,
	TLSF_DATASTRUCT_CORRUPTED      =  3,

	TLSF_STATUS_MAX,
}tlsf_ErrCode;

typedef struct Tlsf_ErrStruct{
	tlsf_ErrCode    err_code;
	void            *mem_ptr;
	U32             block_size;
}Tlsf_ErrStruct;

/* Upto 256 MB Support */
#if(MAX_HEAP_SIZE > 32*MB)
#define MAX_FIRST_LIST               23
#else
#define MAX_FIRST_LIST               20
#endif
#define MAX_SECOND_LIST              32

typedef struct block_header_t block_header_t;

typedef struct block_header_t{
	int header_magic;
	int block_size;
	int payload_size;

	/*Use them for payload in allocated block*/
	block_header_t *next;
	block_header_t *prev;

	/* Tail */
	int tail_magic;
	int t_blk_size;
}block_header_t;

typedef struct tlsf_freelist_t{
	U32 fl_bitmap;
	U32 sl_bitmap[MAX_SECOND_LIST];
	block_header_t *block_table[MAX_FIRST_LIST][MAX_SECOND_LIST];
}tlsf_freelist_t;

typedef struct tlsf_heap_handler_t{
	tlsf_freelist_t freelist_t;
	char *heap_start;
	char *heap_end;
	U32 heap_size;
}tlsf_heap_handler_t;

/*This function is used to allocate the  memory*/    
void *tlsf_alloc(void* handle, U32 size);

/*This function is used to free the allocated memory*/           
void tlsf_free(void* handle, void *mem_ptr);

void *tlsf_alloc_aligned(void *handle, U32 size, U32 align);

/*This function is used to init the memory heap*/
void *tlsf_init_pool(void *pool_start, U32 size);

#ifdef __cplusplus
}
#endif  // __cplusplus

#endif  /*tlsf_h*/
