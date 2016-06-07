#pragma once

#ifndef VSXX_PLUGINMAIN_H_
#define VSXX_PLUGINMAIN_H_

#include <vector>

#include "VapourSynth++.hpp"

struct PluginInfo {
	struct FilterInfo {
		VSPublicFunction factory;
		const char *name;
		const char *arg_str;
		void *construct_arg;

		FilterInfo(VSPublicFunction factory, const char *name, const char *arg_str, void *construct_arg = nullptr) :
			factory{ factory }, name{ name }, arg_str{ arg_str }, construct_arg{ construct_arg }
		{
		}
	};

	const char *identifier;
	const char *plugin_namespace;
	const char *plugin_name;
	std::vector<FilterInfo> filters;
	bool read_only;

	PluginInfo(const char *identifier, const char *plugin_namespace, const char *plugin_name,
	           std::initializer_list<FilterInfo> filters, bool read_only = true) :
		identifier{ identifier }, plugin_namespace{ plugin_namespace }, plugin_name{ plugin_name }, filters{ filters }, read_only{ read_only }
	{
	}
};

// To be implemented by plugin author.
extern const PluginInfo g_plugin_info;

// Provided by vsxx_pluginmain.cpp.
VS_EXTERNAL_API(void) VapourSynthPluginInit(VSConfigPlugin config_func, VSRegisterFunction register_func, VSPlugin *plugin);

#endif // VSXX_PLUGINMAIN_H_
