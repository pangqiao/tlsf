objects := $(patsubst %.c,%.o,$(wildcard *.c))
tlsf : $(objects)
	cc -o tlsf $(objects)
	
.PHONY:clean	
clean :
	rm tlsf $(objects)
