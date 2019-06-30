#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([greybus-bridge], [0.1], [])
AM_INIT_AUTOMAKE([subdir-objects])


# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL

# Checks for libraries.
AC_CHECK_LIB([nl-3], [nl_socket_alloc])
AC_CHECK_LIB([nl-genl-3], [genl_register_family])
AC_CHECK_LIB([pthread], [pthread_create])

# FIXME: @CJF: 20190629: isn't it cheating to just use 'main'??
AC_CHECK_LIB([avahi-common], [main],
	AC_CHECK_LIB([avahi-client], [main],
		[avahi=true],
		[avahi=false]
	)
	,
	[avahi=false]
)

AC_CONFIG_SRCDIR([main.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([
	Makefile
])

AC_ARG_ENABLE([avahi],
[  --enable-avahi    Enable Avahi],
[case "${enableval}" in
	yes) AS_IF([test x$avahi = xtrue],AC_DEFINE([HAVE_AVAHI], [1], ["Avahi support"]));;
	no)  avahi=false ;;
	*) AC_MSG_ERROR([bad value ${enableval} for --enable-avahi]) ;;
esac])
AM_CONDITIONAL([AVAHI], [test x$avahi = xtrue])

AC_ARG_ENABLE([bluetooth],
[  --enable-bluetooth    Enable bluetooth],
[case "${enableval}" in
	yes) bluetooth=true ;
	     AC_CHECK_LIB([bluetooth], [hci_inquiry]) ;;
	no)  bluetooth=false ;;
	*) AC_MSG_ERROR([bad value ${enableval} for --enable-bluetooth]) ;;
esac])
AM_CONDITIONAL([BLUETOOTH], [test x$bluetooth = xtrue])

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
