#include <stdexcept>
#include "vsxx4_pluginmain.h"

using namespace vsxx4;

namespace {

class InvertFilter : public FilterBase {
	FilterNode m_node;
	VSVideoInfo m_vi;
	bool m_enabled;
public:
	InvertFilter(void * = nullptr) : m_vi{}, m_enabled{} {}

	const char *get_name(void *) noexcept override
	{
		return "Invert";
	}

	void init(const ConstMap &in, const Map &out, const Core &core) override
	{
		m_node = in.get_prop<FilterNode>("clip");
		m_vi = m_node.video_info();
		m_enabled = in.get_prop<bool>("enabled", map::default_val(true));

		if (m_vi.format.colorFamily == cfUndefined || m_vi.format.sampleType != stInteger || m_vi.format.bitsPerSample != 8)
			throw std::runtime_error{ "clip must be 8-bit integer" };

		out.set_prop("clip", create_video_filter(m_vi, fmParallel, simple_dep(m_node, rpStrictSpatial), core));
	}

	ConstFrame get_frame_initial(int n, const Core &core, const FrameContext &frame_context, void *) override
	{
		frame_context.request_frame(n, m_node);
		return nullptr;
	}

	ConstFrame get_frame(int n, const Core &core, const FrameContext &frame_context, void *) override
	{
		ConstFrame src = frame_context.get_frame(n, m_node);

		if (!m_enabled)
			return src;

		const VSVideoFormat &format = src.video_format();
		Frame dst = core.new_video_frame(format, src.width(), src.height(), src);

		for (int p = 0; p < format.numPlanes; ++p) {
			const uint8_t *src_p = src.read_ptr(p);
			uint8_t *dst_p = dst.write_ptr(p);

			ptrdiff_t src_stride = src.stride(p);
			ptrdiff_t dst_stride = dst.stride(p);
			unsigned w = src.width(p);
			unsigned h = src.height(p);

			for (unsigned i = 0; i < h; ++i) {
				for (unsigned j = 0; j < w; ++j) {
					dst_p[j] = ~src_p[j];
				}

				src_p += src_stride;
				dst_p += dst_stride;
			}
		}
		return dst;
	}
};

} // namespace


const PluginInfo4 g_plugin_info4 = {
	"com.example.invert", "invert", "VapourSynth4 Invert Example", 0, {
		{ &FilterBase::filter_create<InvertFilter>, "Invert", "clip:vnode;enabled:int:opt;", "clip:vnode;" }
	}
};
