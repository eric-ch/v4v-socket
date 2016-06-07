#
# Autoconf initialisation.
#
AC_INIT(test4v, 1.0)
AC_PREREQ(2.13)
AC_CONFIG_HEADERS(src/config.h)
AC_CONFIG_SRCDIR(src/common/include/utils.h)
AM_INIT_AUTOMAKE([foreign -Wall -Werror])

#
# Version management.
# +1    : 0     Interface changes breaking retro-compatibility.
# 0     : +1    Internal changes without lost of retro-compatibility.
#
VERSION_MAJOR=1
VERSION_MINOR=0
AC_DEFINE_UNQUOTED([VERSION_MAJOR], [$VERSION_MAJOR], [test4v major version number])
AC_DEFINE_UNQUOTED([VERSION_MINOR], [$VERSION_MINOR], [test4v minor version number])

#
# Standard checks.
#
AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_RANLIB

# Compiler capabilities.
AC_C_INLINE
AC_C_CONST

# Xen user-land headers out of tree.
## Modifying CPPFLAGS will allow AC_CHECK_HEADERS() to find these headers where they are.
AC_ARG_WITH(xendir, AC_HELP_STRING([--with-xendir=PATH], [Path to xen header files.]),
            XENDIR=$with_xendir, [])
case "${XENDIR}" in
    ""|"no"|"yes")
        ;;
    *)
        CPPFLAGS="${CPPFLAGS} -I${XENDIR}"
        AC_MSG_NOTICE("CPPFLAGS extended to $CPPFLAGS")
        ;;
esac

# Linux V4V headers out of tree.
## Modifying CPPFLAGS will allow AC_CHECK_HEADERS() to find these headers where they are.
AC_ARG_WITH(v4vdir, AC_HELP_STRING([--with-v4vdir=PATH], [Path to v4v header files.]),
            V4VDIR=$with_v4vdir, [])
case "${V4VDIR}" in
    ""|"no"|"yes")
        ;;
    *)
        CPPFLAGS="${CPPFLAGS} -I${V4VDIR}"
        AC_MSG_NOTICE("CPPFLAGS extended to $CPPFLAGS")
        ;;
esac

# Checks for header files.
AC_CHECK_HEADERS([xen/xen.h])
AC_CHECK_HEADERS([linux/v4v.h])

# Required modules.
PKG_CHECK_MODULES([LIBEVENT], [libevent])

# Output files
AC_OUTPUT([Makefile
	   src/Makefile
	   src/socket-ops/Makefile
	   ])
