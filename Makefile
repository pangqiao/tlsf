objects = main.o tlsf.o
tlsf: $(objects)
	cc -o tlsf $(objects)
main.o:tlsf.h
tlsf.o:tlsf.h 

.PHONY:clean	
clean :
	rm $(objects)