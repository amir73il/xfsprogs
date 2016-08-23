AC_DEFUN([AC_HAVE_ATTRIBUTES_H],
  [ AC_CHECK_HEADERS(attr/attributes.h, [have_attributes_h=yes])
    AC_SUBST(have_attributes_h)
    if test "$have_attributes_h" != "yes"; then
        echo
        echo 'WARNING: attr/attributes.h does not exist.'
        echo 'Install the extended attributes (attr) development package.'
        echo 'Alternatively, run "make install-dev" from the attr source.'
        echo
    fi
  ])

AC_DEFUN([AC_HAVE_ATTRIBUTES_STRUCTS],
  [ AC_CHECK_TYPES([struct attrlist_cursor, struct attr_multiop, struct attrlist_ent],
    [have_attributes_structs=yes],,
    [
#include <sys/types.h>
#include <attr/attributes.h>] )
    AC_SUBST(have_attributes_structs)
  ])

AC_DEFUN([AC_HAVE_ATTRIBUTES_MACROS],
  [ AC_TRY_LINK([
#include <sys/types.h>
#include <attr/attributes.h>],
    [ int x = ATTR_SECURE; int y = ATTR_ROOT; int z = ATTR_TRUST; ATTR_ENTRY(0, 0); ],
    [have_attributes_macros=yes])
    AC_SUBST(have_attributes_macros)
  ])
