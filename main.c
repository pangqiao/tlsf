/*main.c : This file contains the 'main' function. 
Program execution begins and ends there.*/


#include <stdio.h>
#include "tlsf.h"

int main(int argc, char* argv[])
{
	Tlsf_ErrStruct tlsf_error;
	
	U32 *ptr = NULL;

	tlsf_init();

	ptr = malloc_test(4096);
	
	PRINT_MSG("Malloc:0x%x.\n", (U32)ptr);
	
	if (ptr != NULL){
		free_test(ptr);	
		PRINT_MSG("Free:0x%x.\n", (U32)ptr);
		ptr = NULL;
	}

	
	return 0;
}


