#include <cmath>
#include <cstdint>
#include <stdexcept>
#include <type_traits>
#include <VSHelper4.h>
#include "vsxx4_pluginmain.h"

using namespace vsxx4;

namespace {

template <class T>
double psnr_plane(const void *dis, ptrdiff_t dis_stride, const void *ref, ptrdiff_t ref_stride, unsigned width, unsigned height, unsigned bits)
{
	const T *disp = static_cast<const T *>(dis);
	const T *refp = static_cast<const T *>(ref);
	double max = std::is_integral<T>::value ? static_cast<double>((1ULL << bits) - 1) : 1.0;
	double mse = 0.0;

	for (unsigned i = 0; i < height; ++i) {
		for (unsigned j = 0; j < width; ++j) {
			double x = disp[j] - refp[j];
			mse += x * x;
		}

		disp += dis_stride / sizeof(T);
		refp += ref_stride / sizeof(T);
	}

	mse /= static_cast<double>(width) * height;
	return 10 * std::log10(max * max / mse);
}


class PSNRFilter : public FilterBase {
	FilterNode m_dis_node;
	FilterNode m_ref_node;
public:
	PSNRFilter(void * = nullptr) {}

	const char *get_name(void *) noexcept override
	{
		return "PSNR";
	}

	void init(const ConstMap &in, const Map &out, const Core &core) override
	{
		m_dis_node = in.get_prop<FilterNode>("clip");
		m_ref_node = in.get_prop<FilterNode>("clip2");

		const VSVideoInfo &vi = m_dis_node.video_info();

		if (!vsh::isConstantVideoFormat(&vi))
			throw std::runtime_error{ "constant format required" };
		if (!vsh::isSameVideoInfo(&vi, &m_ref_node.video_info()))
			throw std::runtime_error{ "matching formats required" };
		if ((vi.format.sampleType == stInteger && vi.format.bytesPerSample > 2) || (vi.format.sampleType == stFloat && vi.format.bytesPerSample != 4))
			throw std::runtime_error{ "unsupported pixel format" };

		create_video_filter(out, vi, fmParallel, make_deps().add_dep(m_dis_node, rpStrictSpatial).add_dep(m_ref_node, rpStrictSpatial), core);
	}

	ConstFrame get_frame_initial(int n, const Core &core, const FrameContext &frame_context, void *) override
	{
		frame_context.request_frame(n, m_dis_node);
		frame_context.request_frame(n, m_ref_node);
		return nullptr;
	}

	ConstFrame get_frame(int n, const Core &core, const FrameContext &frame_context, void *) override
	{
		Frame dis = core.copy_frame(frame_context.get_frame(n, m_dis_node));
		ConstFrame ref = frame_context.get_frame(n, m_ref_node);

		const VSVideoFormat &format = dis.video_format();
		MapRef props = dis.frame_props_rw();
		props.erase("psnr");

		for (unsigned p = 0; p < static_cast<unsigned>(format.numPlanes); ++p) {
			const uint8_t *refp = ref.read_ptr(p);
			const uint8_t *disp = dis.read_ptr(p);
			ptrdiff_t ref_stride = ref.stride(p);
			ptrdiff_t dis_stride = dis.stride(p);
			unsigned width = dis.width(p);
			unsigned height = dis.height(p);

			double psnr = NAN;

			if (format.sampleType == stInteger && format.bytesPerSample == 1)
				psnr = psnr_plane<uint8_t>(disp, dis_stride, refp, ref_stride, width, height, format.bitsPerSample);
			else if (format.sampleType == stInteger && format.bytesPerSample == 2)
				psnr = psnr_plane<uint16_t>(disp, dis_stride, refp, ref_stride, width, height, format.bitsPerSample);
			else if (format.sampleType == stFloat && format.bytesPerSample == 4)
				psnr = psnr_plane<float>(disp, dis_stride, refp, ref_stride, width, height, format.bitsPerSample);

			props.set_prop("psnr", psnr, maAppend);
		}

		return dis;
	}
};

} // namespace


const PluginInfo4 g_plugin_info4 = {
	"com.example.psnr", "psnr", "VapourSynth4 PSNR Example", 0, {
		{ &FilterBase::filter_create<PSNRFilter>, "PSNR", "clip:vnode;clip2:vnode;", "clip:vnode;" }
	}
};
