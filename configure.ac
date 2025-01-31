#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([greybus-bridge], [0.1], [])
AM_INIT_AUTOMAKE([subdir-objects foreign])


# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL

# Checks for libraries.
AC_CHECK_LIB([nl-3], [nl_socket_alloc])
AC_CHECK_LIB([nl-genl-3], [genl_register_family])
AC_CHECK_LIB([pthread], [pthread_create])
AC_CHECK_LIB([avahi-common], [main])
AC_CHECK_LIB([avahi-client], [main])

AC_CONFIG_SRCDIR([main.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([
	Makefile
])

AC_ARG_ENABLE([bluetooth],
[  --enable-bluetooth    Enable bluetooth],
[case "${enableval}" in
	yes) bluetooth=true ;
	     AC_CHECK_LIB([bluetooth], [hci_inquiry]) ;;
	no)  bluetooth=false ;;
	*) AC_MSG_ERROR([bad value ${enableval} for --enable-bluetooth]) ;;
esac])
AM_CONDITIONAL([BLUETOOTH], [test x$bluetooth = xtrue])

AC_ARG_ENABLE([tcpip],
[  --enable-tcpip    Enable TCP/IP],
[case "${enableval}" in
	yes) tcpip=true ;
	     AC_DEFINE([HAVE_TCPIP], [1], ["TCP/IP support"]) ;;
	no)  tcpip=false ;;
	*) AC_MSG_ERROR([bad value ${enableval} for --enable-tcpip]) ;;
esac])
AM_CONDITIONAL([TPCIP], [test x$tcpip = xtrue])

# see autotools mythbuster
with_ssl="auto"
AC_ARG_WITH(
	[ssl],
	[AS_HELP_STRING(
		[--with-ssl],
		[Enable ssl]
	)]
)
AS_IF(
	[test "x$with_ssl" != "xno"],

	[PKG_CHECK_MODULES(
		[SSL],
		[openssl],
		[have_ssl=yes],
		[have_ssl=no]
	)],

	[have_ssl=no]
)
AS_IF(
	[test "x$have_ssl" = "xyes"],
	[
		AC_SUBST([SSL_LIBS])
		AC_SUBST([SSL_CFLAGS])
		AC_DEFINE([SSL], [1], ["SSL support"])
	],
	[AS_IF([test "x$with_ssl" = "xyes"],
		[AC_MSG_ERROR([ssl requested but not found])
	])
])
AM_CONDITIONAL([SSL],[test "x$have_ssl" = "xyes"])

AC_ARG_ENABLE([uart],
[  --enable-uart    Enable uart],
[case "${enableval}" in
	yes) uart=true ;
	     AC_DEFINE([HAVE_UART], [1], ["UART support"]) ;;
	no)  uart=false ;;
	*) AC_MSG_ERROR([bad value ${enableval} for --enable-uart]) ;;
esac])
AM_CONDITIONAL([UART], [test x$uart = xtrue])

AC_ARG_ENABLE([netlink],
[  --enable-netlink    Enable Netlink],
[case "${enableval}" in
	yes) netlink=true ;
	     AC_DEFINE([NETLINK], [1], ["Netlink support"]) ;;
	no)  netlink=false ;;
	*) AC_MSG_ERROR([bad value ${enableval} for --enable-netlink]) ;;
esac])
AM_CONDITIONAL([NETLINK], [test x$netlink = xtrue])

AC_ARG_ENABLE([gbsim],
[  --enable-gbsim    Enable GBSIM],
[case "${enableval}" in
	yes) gbsim=true ;
	     AC_DEFINE([GBSIM], [1], ["GBSIM support"]) ;;
	no)  gbsim=false ;;
	*) AC_MSG_ERROR([bad value ${enableval} for --enable-gbsim]) ;;
esac])
AM_CONDITIONAL([GBSIM], [test x$gbsim = xtrue])

AC_ARG_VAR([GBDIR], ["greybus sources directory"])
AS_IF([test "$GBDIR" = ""], [
  AC_MSG_ERROR([Environment variable GBDIR needs to be set])
])

AC_OUTPUT
