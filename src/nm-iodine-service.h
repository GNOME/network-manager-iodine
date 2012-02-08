/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */
/* NetworkManager -- Network link manager
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Copyright © 2012 Guido Günther <agx@sigxcpu.org>
 */

#ifndef NM_IODINE_PLUGIN_H
#define NM_IODINE_PLUGIN_H

#include <glib.h>
#include <nm-vpn-plugin.h>

#define NM_TYPE_IODINE_PLUGIN            (nm_iodine_plugin_get_type ())
#define NM_IODINE_PLUGIN(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_IODINE_PLUGIN, NMIODINEPlugin))
#define NM_IODINE_PLUGIN_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_IODINE_PLUGIN, NMIODINEPluginClass))
#define NM_IS_IODINE_PLUGIN(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_IODINE_PLUGIN))
#define NM_IS_IODINE_PLUGIN_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_IODINE_PLUGIN))
#define NM_IODINE_PLUGIN_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_IODINE_PLUGIN, NMIODINEPluginClass))

#define NM_DBUS_SERVICE_IODINE    "org.freedesktop.NetworkManager.iodine"
#define NM_DBUS_INTERFACE_IODINE  "org.freedesktop.NetworkManager.iodine"
#define NM_DBUS_PATH_IODINE       "/org/freedesktop/NetworkManager/iodine"

#define NM_IODINE_KEY_TOPDOMAIN "topdomain"
#define NM_IODINE_KEY_NAMESERVER "nameserver"
#define NM_IODINE_KEY_FRAGSIZE "fragsize"
#define NM_IODINE_KEY_PASSWORD "password"

typedef struct {
	NMVPNPlugin parent;
} NMIODINEPlugin;

typedef struct {
	NMVPNPluginClass parent;
} NMIODINEPluginClass;

GType nm_iodine_plugin_get_type (void);

NMIODINEPlugin *nm_iodine_plugin_new (void);

#endif /* NM_IODINE_PLUGIN_H */
