MAKEFLAGS += --no-builtin-rules

V ?= $(VERBOSE)
ifeq ($(V),1)
	Q :=
	VECHO := @true
	MAKEMINS :=
else
	Q := @
	VECHO := @echo
	MAKEMINS := -s
endif

CPP				:=	g++

CWD					!=	/bin/pwd
MAGICK_CFLAGS		!=	pkg-config --cflags Magick++
MAGICK_LIBS			!=	pkg-config --libs Magick++
DBUS_CFLAGS			!=  pkg-config --cflags dbus-1
DBUS_LIBS			!=  pkg-config --libs dbus-1
DBUS_TINY_CFLAGS	:=	-I$(PWD)/DBUS-Tiny -Iesp32-common -I.
DBUS_TINY_LIBS		:=	-L$(PWD)/DBUS-Tiny -Wl,-rpath=$(CWD)/DBUS-Tiny -ldbus-tiny

CPPFLAGS		:= -O3 -std=gnu++23 -Wl,--copy-dt-needed-entries -fPIC $(MAGICK_CFLAGS) $(DBUS_CFLAGS) $(DBUS_TINY_CFLAGS) \
					-lpthread -lbluetooth $(MAGICK_LIBS) $(DBUS_LIBS) $(DBUS_TINY_LIBS) \
					-lboost_system -lboost_program_options -lboost_regex -lboost_thread -lboost_chrono -lboost_json -lmbedtls

OBJS			:= e32if.o generic_socket.o ip_socket.o tcp_socket.o udp_socket.o bt_socket.o esp32-common/packet.o util.o esp32-common/crypt.o esp32-common/exception.o
HDRS			:= e32if.h generic_socket.h ip_socket.h tcp_socket.h udp_socket.h bt_socket.h esp32-common/packet.h util.h esp32-common/crypt.h esp32-common/exception.h
BIN				:= e32if

.PRECIOUS:		*.cpp *.i
.PHONY:			all

all:			$(BIN)

clean:
				$(VECHO) "CLEAN"
				-$(Q) rm -rf $(OBJS) main.o $(BIN) 2> /dev/null

e32if.o:		$(HDRS)
generic_socket.o: $(HDRS)
bt_socket.o:	$(HDRS)
ip_socket.o:	$(HDRS)
tcp_socket.o:	$(HDRS)
udp_socket.o:	$(HDRS)
main.o:			$(HDRS)
packet.o:		$(HDRS)
util.o:			$(HDRS)

%.o:			%.cpp
				$(VECHO) "CPP $< -> $@"
				$(Q) $(CPP) @gcc-warnings $(CPPFLAGS) -c $< -o $@

$(BIN):			$(OBJS) main.o
				$(VECHO) "LD $(OBJS) main.o -> $@"
				$(Q) $(CPP) @gcc-warnings $(CPPFLAGS) $(OBJS) main.o -o $@
