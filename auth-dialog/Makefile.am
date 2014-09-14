INCLUDES = -I${top_srcdir}

libexec_PROGRAMS = nm-iodine-auth-dialog

nm_iodine_auth_dialog_CPPFLAGS = \
	$(NM_CFLAGS) \
	$(GTHREAD_CFLAGS) \
	$(GTK_CFLAGS) \
        $(LIBSECRET_CFLAGS) \
	-DICONDIR=\""$(datadir)/pixmaps"\" \
	-DBINDIR=\""$(bindir)"\" \
	-DG_DISABLE_DEPRECATED \
	-DGDK_DISABLE_DEPRECATED \
	-DGNOME_DISABLE_DEPRECATED \
	-DGNOMELOCALEDIR=\"$(datadir)/locale\" \
	-DVERSION=\"$(VERSION)\"

nm_iodine_auth_dialog_SOURCES = \
	main.c \
	vpn-password-dialog.c \
	vpn-password-dialog.h \
	$(NULL)

nm_iodine_auth_dialog_LDADD = \
	$(GTK_LIBS) \
	$(NM_LIBS) \
        $(LIBSECRET_LIBS)

CLEANFILES = *~

