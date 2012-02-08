AUTOMAKE_OPTIONS = foreign

SUBDIRS = src

if WITH_GNOME
SUBDIRS += properties po

if WITH_AUTHDLG
SUBDIRS += auth-dialog
endif
endif

dbusservicedir = $(sysconfdir)/dbus-1/system.d
dbusservice_DATA = nm-iodine-service.conf

nmvpnservicedir = $(sysconfdir)/NetworkManager/VPN
nmvpnservice_DATA = nm-iodine-service.name

nm-iodine-service.name: $(srcdir)/nm-iodine-service.name.in
	sed -e 's|[@]LIBEXECDIR[@]|$(libexecdir)|g' $< >$@

EXTRA_DIST = nm-iodine-service.name.in \
             $(dbusservice_DATA)  \
             $(desktop_in_files)  \
             $(icon_DATA)         \
             intltool-extract.in  \
             intltool-merge.in    \
             intltool-update.in

CLEANFILES = $(nmvpnservice_DATA) $(desktop_DATA) *~
DISTCLEANFILES = intltool-extract intltool-merge intltool-update

ACLOCAL_AMFLAGS = -I m4