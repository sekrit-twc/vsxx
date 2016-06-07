#include "vsxx_pluginmain.h"

VS_EXTERNAL_API(void) VapourSynthPluginInit(VSConfigPlugin config_func, VSRegisterFunction register_func, VSPlugin *plugin)
{
	const PluginInfo &info = g_plugin_info;

	config_func(info.identifier, info.plugin_namespace, info.plugin_name, VAPOURSYNTH_API_VERSION, info.read_only, plugin);
	for (const auto &f : info.filters) {
		register_func(f.name, f.arg_str, f.factory, f.construct_arg, plugin);
	}
}
