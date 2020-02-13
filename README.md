# tlsf
 TLSF (Two-Level Segregate Fit) is a general purpose dynamic memory allocator specifically designed to meet real-time requirements.
# Notes
 1. Low fragmentation.
 2. 4-byte alignment.
 3. data structure checking.
 4. The TLSF allocator has been released under a dual license scheme: [GPL](http://www.gnu.org/licenses/gpl-3.0.html) and [LGPL](http://www.gnu.org/licenses/lgpl-3.0.html).
# API Usage
```
#include <stdio.h>
#include "tlsf.h"

char pool[MAX_HEAP_SIZE];
tlsf_heap_handler_t *instance;

int main(int argc, char* argv[])
{
	Tlsf_ErrStruct tlsf_error;
	handle = (tlsf_heap_handler_t *)tlsf_init_pool(&pool[0], MAX_HEAP_SIZE);
	void * data = tlsf_alloc(handle, 4096, &tlsf_error);
	
	if (data != NULL){
		tlsf_free(handle, data, &tlsf_error);	
		data = NULL;
	}

	return 0;
}
```
# History
2012/02/212 - v1.0
- First release

# Reference
1. http://www.gii.upv.es/tlsf/
2. https://pdfs.semanticscholar.org/31da/f60a6c47c1bf892a2c4b76e4bb7c1cf83b58.pdf
 
