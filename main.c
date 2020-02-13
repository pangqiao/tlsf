/*main.c : This file contains the 'main' function. 
Program execution begins and ends there.*/


#include <stdio.h>
#include "tlsf.h"


char pool[MAX_HEAP_SIZE];
tlsf_heap_handler_t *instance;

int main(int argc, char* argv[])
{
	Tlsf_ErrStruct tlsf_error;
	
	instance = (tlsf_heap_handler_t *)tlsf_init_pool(&pool[0], MAX_HEAP_SIZE);

	void * data = tlsf_alloc(instance, 4096, &tlsf_error);
	
	if (data != NULL){
		tlsf_free(instance, data, &tlsf_error);	
		data = NULL;
	}

	return 0;
}

