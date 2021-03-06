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
tlsf_heap_handler_t *handle;

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
2020/12/29 - v2.0
- Optimize find_alloc_index;
- Fix bug: add fill_head and fill_tail and marked with allocated
   to avoid the block_merge_next or block_merge_prev out of heap range.

2020/03/21 - v1.1
- Add tlsf_reallocate and tlsf_alloc_aligned

2020/02/21 - v1.0
- First release

# Reference
1. http://www.gii.upv.es/tlsf/
2. https://pdfs.semanticscholar.org/31da/f60a6c47c1bf892a2c4b76e4bb7c1cf83b58.pdf
 
