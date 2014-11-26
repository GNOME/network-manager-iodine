plugindir = $(libdir)/NetworkManager
plugin_LTLIBRARIES = libnm-iodine-properties.la

libnm_iodine_properties_la_SOURCES = \
	nm-iodine.c \
	nm-iodine.h

uidir = $(datadir)/gnome-vpn-properties/iodine
ui_DATA = nm-iodine-dialog.ui

libnm_iodine_properties_la_CFLAGS =                	\
        $(GTK_CFLAGS)                                   \
        $(NM_CFLAGS)                        		\
	-I$(top_srcdir)/src				\
        -DICONDIR=\""$(datadir)/pixmaps"\"              \
        -DUIDIR=\""$(uidir)"\"                          \
        -DG_DISABLE_DEPRECATED                          \
        -DGDK_DISABLE_DEPRECATED                        \
        -DGNOME_DISABLE_DEPRECATED                      \
        -DGNOMELOCALEDIR=\"$(datadir)/locale\"		\
        -DVERSION=\"$(VERSION)\"

libnm_iodine_properties_la_LIBADD = \
        $(GTK_LIBS) \
        $(NM_LIBS)

libnm_iodine_properties_la_LDFLAGS =      \
        -avoid-version

CLEANFILES = *.bak *~

EXTRA_DIST =                            \
        $(ui_DATA)
