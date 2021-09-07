#ifndef VSXX4_PLUGINMAIN_H_
#define VSXX4_PLUGINMAIN_H_

#include <vector>

#include "VapourSynth4++.hpp"

struct PluginInfo4 {
	struct FilterInfo {
		VSPublicFunction factory;
		const char *name;
		const char *arg_str;
		const char *return_type;
		void *construct_arg;

		FilterInfo(VSPublicFunction factory, const char *name, const char *arg_str, const char *return_type, void *construct_arg = nullptr) :
			factory{ factory }, name{ name }, arg_str{ arg_str }, return_type{ return_type }, construct_arg{ construct_arg }
		{}
	};

	const char *identifier;
	const char *plugin_namespace;
	const char *plugin_name;
	int plugin_version;
	std::vector<FilterInfo> filters;
	::VSPluginConfigFlags flags;

	PluginInfo4(const char *identifier, const char *plugin_namespace, const char *plugin_name, int plugin_version,
		        std::initializer_list<FilterInfo> filters, ::VSPluginConfigFlags flags = {}) :
		identifier{ identifier },
		plugin_namespace{ plugin_namespace },
		plugin_name{ plugin_name },
		plugin_version{ plugin_version },
		filters{ filters },
		flags{ flags }
	{}
};

// To be implemented by plugin author.
extern const PluginInfo4 g_plugin_info4;

// Provided by vsxx4_pluginmain.cpp.
VS_EXTERNAL_API(void) VapourSynthPluginInit2(::VSPlugin *plugin, const ::VSPLUGINAPI *vspapi);

#endif // VSXX4_PLUGINMAIN_H_
