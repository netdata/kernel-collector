// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef _NETDATA_DEFS_
#define _NETDATA_DEFS_ 1

enum netdata_controller {
    NETDATA_CONTROLLER_APPS_ENABLED,
    NETDATA_CONTROLLER_APPS_LEVEL,

    NETDATA_CONTROLLER_END
};

enum netdata_apps_level {
    NETDATA_APPS_LEVEL_REAL_PARENT,
    NETDATA_APPS_LEVEL_PARENT,
    NETDATA_APPS_LEVEL_ALL,
};

#endif

