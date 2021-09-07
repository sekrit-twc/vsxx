#include "vsxx4_pluginmain.h"

VS_EXTERNAL_API(void) VapourSynthPluginInit2(::VSPlugin *plugin, const ::VSPLUGINAPI *vspapi)
{
	if (vspapi->getAPIVersion() < VAPOURSYNTH_API_VERSION)
		return;

	const PluginInfo4 &info = g_plugin_info4;

	vspapi->configPlugin(info.identifier, info.plugin_namespace, info.plugin_name, info.plugin_version, VAPOURSYNTH_API_VERSION, info.flags, plugin);
	for (const auto &f : info.filters) {
		vspapi->registerFunction(f.name, f.arg_str, f.return_type, f.factory, f.construct_arg, plugin);
	}
}
