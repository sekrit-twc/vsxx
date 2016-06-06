#include <stdexcept>
#include "vsxx_pluginmain.h"

using namespace vsxx;

class InvertFilter : public FilterBase {
	FilterNode m_node;
	VSVideoInfo m_vi;
	bool m_enabled;
public:
	InvertFilter(void * = nullptr) : m_vi(), m_enabled{} {}

	const char *get_name(int) noexcept override
	{
		return "Invert";
	}

	std::pair<VSFilterMode, int> init(const ConstPropertyMap &in, const PropertyMap &out, const VapourCore &core)
	{
		m_node = in.get_prop<FilterNode>("clip");
		m_vi = m_node.video_info();
		m_enabled = in.get_prop<bool>("enabled", map::default_val(true));

		if (!m_vi.format || m_vi.format->sampleType != stInteger || m_vi.format->bitsPerSample != 8)
			throw std::runtime_error{ "clip must be 8-bit integer" };

		return{ fmParallel, 0 };
	}

	std::pair<const VSVideoInfo *, size_t> get_video_info() noexcept override
	{
		return{ &m_vi, 1 };
	}

	void get_frame_initial(int n, const VapourCore &, VSFrameContext *frame_ctx) override
	{
		m_node.request_frame_filter(n, frame_ctx);
	}

	ConstVideoFrame get_frame(int n, const VapourCore &core, VSFrameContext *frame_ctx) override
	{
		ConstVideoFrame src = m_node.get_frame_filter(n, frame_ctx);

		if (!m_enabled)
			return src;

		const VSFormat &format = src.format();
		VideoFrame dst = core.new_video_frame(format, src.width(0), src.height(0));

		for (int p = 0; p < format.numPlanes; ++p) {
			const uint8_t *src_p = src.read_ptr(p);
			uint8_t *dst_p = dst.write_ptr(p);

			int src_stride = src.stride(p);
			int dst_stride = dst.stride(p);
			int w = src.width(p);
			int h = src.height(p);

			for (int i = 0; i < h; ++i) {
				for (int j = 0; j < w; ++j) {
					dst_p[j] = ~src_p[j];
				}
				src_p += src_stride;
				dst_p += dst_stride;
			}
		}
		return dst;
	}
};

const PluginInfo g_plugin_info = {
	"com.example.invert", "invert", "VapourSynth Invert Example", {
		{ &FilterBase::filter_create<InvertFilter>, "Invert", "clip:clip;enabled:int:opt;" }
	}
};
