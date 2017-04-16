CPP      = g++
CC       = gcc
CFLAGS   = -g -Wall
OBJ      = main.o formatdatetime.o getpacket.o regexhttpparser.o
LINKOBJ  = main.o formatdatetime.o getpacket.o regexhttpparser.o
BIN      = parserhttp
RM       = rm -rf
LIB	 = -lpcap /usr/local/lib/libboost_regex.so
$(BIN): $(OBJ)
	$(CPP) $(LINKOBJ) -o $(BIN)   $(LIB) $(CFLAGS) 

	
clean: 
	${RM} $(OBJ) $(BIN)

cleanobj:
	${RM} *.o
