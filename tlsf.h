#if !defined (tlsf_h)
#define tlsf_h


#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

typedef unsigned int U32;
typedef int BOOL;
typedef unsigned char U8;


#define USE_PRINTF
#ifdef USE_PRINTF
#define PRINT_MSG(fmt, args...)  printf(fmt, ##args)
#else
#define PRINT_MSG(fmt, args...)
#endif

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

void *malloc_test(U32 size);
void free_test(void *mem_ptr);

/*This function is used to allocate the  memory*/    
void *tlsf_alloc(void* handle, U32 size, Tlsf_ErrStruct *error);

/*This function is used to free the allocated memory*/           
void tlsf_free(void* handle, void *mem_ptr, Tlsf_ErrStruct *error);

/*This function is used to free the allocated memory*/
void tlsf_trap(Tlsf_ErrStruct *error);

/*This function is used to init the memory heap*/
void tlsf_init(void);

#ifdef __cplusplus
}
#endif  // __cplusplus

#endif  /*tlsf_h*/
