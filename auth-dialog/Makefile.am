libexec_PROGRAMS = nm-iodine-auth-dialog

nm_iodine_auth_dialog_CPPFLAGS = \
	$(GTK_CFLAGS) \
        $(LIBSECRET_CFLAGS) \
	$(LIBNM_GLIB_CFLAGS) \
	$(LIBNM_GTK_CFLAGS) \
	-DICONDIR=\""$(datadir)/pixmaps"\" \
	-DBINDIR=\""$(bindir)"\" \
	-DG_DISABLE_DEPRECATED \
	-DGDK_DISABLE_DEPRECATED \
	-DGNOME_DISABLE_DEPRECATED \
	-DGNOMELOCALEDIR=\"$(datadir)/locale\" \
	-DVERSION=\"$(VERSION)\"

nm_iodine_auth_dialog_SOURCES = \
	main.c \
	$(NULL)

nm_iodine_auth_dialog_LDADD = \
	$(GTK_LIBS) \
	$(LIBNM_GLIB_LIBS) \
	$(LIBNM_GTK_LIBS) \
        $(LIBSECRET_LIBS)

CLEANFILES = *~

