/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * GNOME UI dialogs for configuring iodine VPN connections
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

#ifndef _NM_IODINE_H_
#define _NM_IODINE_H_

#include <glib-object.h>

typedef enum
{
	IODINE_PLUGIN_UI_ERROR_UNKNOWN = 0,
	IODINE_PLUGIN_UI_ERROR_INVALID_PROPERTY,
	IODINE_PLUGIN_UI_ERROR_MISSING_PROPERTY
} IodinePluginUiError;


GQuark iodine_plugin_ui_error_quark (void);
#define IODINE_PLUGIN_UI_ERROR iodine_plugin_ui_error_quark ()

#define IODINE_TYPE_PLUGIN_UI_ERROR (iodine_plugin_ui_error_get_type ()) 
GType iodine_plugin_ui_error_get_type (void);

#define IODINE_TYPE_PLUGIN_UI            (iodine_plugin_ui_get_type ())
#define IODINE_PLUGIN_UI(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), IODINE_TYPE_PLUGIN_UI, IodinePluginUi))
#define IODINE_PLUGIN_UI_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), IODINE_TYPE_PLUGIN_UI, IodinePluginUiClass))
#define IODINE_IS_PLUGIN_UI(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), IODINE_TYPE_PLUGIN_UI))
#define IODINE_IS_PLUGIN_UI_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), IODINE_TYPE_PLUGIN_UI))
#define IODINE_PLUGIN_UI_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), IODINE_TYPE_PLUGIN_UI, IodinePluginUiClass))

typedef struct _IodinePluginUi IodinePluginUi;
typedef struct _IodinePluginUiClass IodinePluginUiClass;

struct _IodinePluginUi {
	GObject parent;
};

struct _IodinePluginUiClass {
	GObjectClass parent;
};

GType iodine_plugin_ui_get_type (void);


#define IODINE_TYPE_PLUGIN_UI_WIDGET            (iodine_plugin_ui_widget_get_type ())
#define IODINE_PLUGIN_UI_WIDGET(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), IODINE_TYPE_PLUGIN_UI_WIDGET, IodinePluginUiWidget))
#define IODINE_PLUGIN_UI_WIDGET_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), IODINE_TYPE_PLUGIN_UI_WIDGET, IodinePluginUiWidgetClass))
#define IODINE_IS_PLUGIN_UI_WIDGET(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), IODINE_TYPE_PLUGIN_UI_WIDGET))
#define IODINE_IS_PLUGIN_UI_WIDGET_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), IODINE_TYPE_PLUGIN_UI_WIDGET))
#define IODINE_PLUGIN_UI_WIDGET_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), IODINE_TYPE_PLUGIN_UI_WIDGET, IodinePluginUiWidgetClass))

typedef struct _IodinePluginUiWidget IodinePluginUiWidget;
typedef struct _IodinePluginUiWidgetClass IodinePluginUiWidgetClass;

struct _IodinePluginUiWidget {
	GObject parent;
};

struct _IodinePluginUiWidgetClass {
	GObjectClass parent;
};

GType iodine_plugin_ui_widget_get_type (void);

#endif	/* _NM_IODINE_H_ */

