CPP      = g++
CC       = gcc
CFLAGS   = -g -Wall
OBJ      = main.o formatdatetime.o getpacket.o
LINKOBJ  = main.o formatdatetime.o getpacket.o 
BIN      = parserhttp
RM       = rm -rf
LIB	 = -lpcap
$(BIN): $(OBJ)
	$(CPP) $(LINKOBJ) -o $(BIN)   $(LIB) $(CFLAGS) 

	
clean: 
	${RM} $(OBJ) $(BIN)

cleanobj:
	${RM} *.o
