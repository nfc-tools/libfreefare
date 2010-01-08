LMF_SRCDIR=	${.CURDIR}/../libfreefare
.PATH:		${LMF_SRCDIR}

#LMF_SRCS!=	${MAKE} -f ${LMF_SRCDIR}/Makefile -V SRCS
LMF_SRCS=	${LMF_SRCDIR}/mifare_classic.c \
		${LMF_SRCDIR}/mad.c \
		${LMF_SRCDIR}/mifare_application.c

TESTS=		test_read_sector_0.c \
		test_authenticate.c \
		test_value_block.c \
		test_access_bits.c \
		test_format.c \
		test_create_trailer_block.c \
		test_mad.c \
		test_mifare_application.c

SRCS=		${LMF_SRCS} \
		${TESTS} \
		main.c \
		mifare_classic_test.c

# list.h must be up-to-date before building main.o
main.o: list.h

NO_MAN=

PROG=		libfreefare_test
INTERNALPROG=	yes
LDADD+=		-lnfc

CFLAGS+=	-std=c99
CFLAGS+=	-ggdb
CFLAGS+=	-Wall -pedantic
CFLAGS+=	-I${LMF_SRCDIR} -I. -I..

.PHONY: check test
check test: libfreefare_test
	./libfreefare_test

# list.h is just a list of all tests, as indicated by DEFINE_TEST macro lines
list.h: ${TESTS} Makefile
	(cd ${.CURDIR}; cat ${TESTS}) | grep DEFINE_TEST > list.h

CLEANFILES+=	list.h

cleantest:
	-chmod -R +w /tmp/${PROG}.*
	-rm -rf /tmp/${PROG}.*

.include <bsd.prog.mk>
