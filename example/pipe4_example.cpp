#define VS_GRAPH_API

#include <cassert>
#include <chrono>
#include <cinttypes>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <map>
#include <mutex>
#include <string>
#include <unordered_map>

#ifdef _WIN32
#include <Windows.h>
#include <fcntl.h>
#include <io.h>
#include <tchar.h>

// MSVC wfprintf incorrectly handles 's' format types.
#ifdef _UNICODE
#define FMT_S _T("S")
#define FMT_TS _T("Ts")
#else
#define FMT_S _T("s")
#define FMT_TS _T("s")
#endif

#define __ORDER_BIG_ENDIAN__ 1234
#define __ORDER_LITTLE_ENDIAN__ 4321
#define __BYTE_ORDER__ __ORDER_LITTLE_ENDIAN__
#else
#include <dlfcn.h>
#include <endian.h>

#define _fputts std::fputs
#define _tcscmp std::strcmp
#define _ftprintf std::fprintf
#define _tfopen std::fopen
#define _tmain main
#define _tperror std::perror
#define _TCHAR char
#define _T(x) x

#define FMT_S "s"
#define FMT_TS "s"
#endif

#include <VSHelper4.h>
#include <VSScript4.h>
#include "VapourSynth4++.hpp"

namespace {

typedef std::basic_string<_TCHAR> tstring;

struct BadCommandLine : public std::runtime_error {
	BadCommandLine() : std::runtime_error("") {}
};

struct ScriptError : public std::runtime_error {
	using std::runtime_error::runtime_error;
};

enum class OutputMode {
	RAW,
	WAVE,
	WAVE64,
	Y4M,
};

struct Arguments {
	tstring in_path;
	tstring out_path;
	tstring tc_path;
	std::unordered_multimap<tstring, tstring> script_args;
	OutputMode mode = OutputMode::RAW;
	int64_t start_frame_or_sample = 0;
	int64_t end_frame_or_sample = -1;
	int out_idx = 0;
	int num_requests = 0;
	bool help = false;
	bool info = false;
	bool progress = false;
	bool version = false;
	bool perf_counters = false;
	bool reflection = false;
	bool verbose_reflection = false;
};

class FpsCounter {
	std::chrono::high_resolution_clock::time_point m_time;
	int m_frames;
public:
	FpsCounter() : m_time{ std::chrono::high_resolution_clock::now() }, m_frames{} {}

	double update()
	{
		auto now = std::chrono::high_resolution_clock::now();
		++m_frames;

		if (now - m_time > std::chrono::seconds{ 10 }) {
			double elapsed = std::chrono::duration_cast<std::chrono::duration<double>>(now - m_time).count();
			int elapsed_frames = m_frames;

			m_frames = 0;
			m_time = now;

			return elapsed_frames / elapsed;
		} else {
			return NAN;
		}
	}
};

class VSScriptLibrary {
	static void *s_handle;
	static const VSSCRIPTAPI *s_vss;

	static void load_library()
	{
		const VSSCRIPTAPI *VS_CC(*get_vss)(int) = nullptr;

#ifdef _WIN32
		s_handle = LoadLibrary(_T("vsscript.dll"));
#else
		s_handle = dlopen("vsscript", RTLD_NOW | RTLD_LOCAL);
#endif
		if (!s_handle)
			return;

		void *proc = nullptr;
#ifdef _WIN32
		proc = GetProcAddress(static_cast<HMODULE>(s_handle), "getVSScriptAPI");
#else
		proc = dlsym(s_handle, "getVSScriptAPI")
#endif
		get_vss = reinterpret_cast<const VSSCRIPTAPI * VS_CC(*)(int)>(proc);
		if (!get_vss)
			return;

		s_vss = get_vss(VSSCRIPT_API_VERSION);
		if (!s_vss)
			return;

		vsxx4::set_vsapi(s_vss->getVSAPI(VAPOURSYNTH_API_VERSION));
	}
public:
	static const VSSCRIPTAPI *get()
	{
		std::once_flag flag;
		std::call_once(flag, load_library);
		if (!s_vss)
			throw ScriptError{ "error loading vsscript" };
		return s_vss;
	}

	static void ensure() { get(); }
};

void *VSScriptLibrary::s_handle = nullptr;
const VSSCRIPTAPI *VSScriptLibrary::s_vss;

struct FileCloser {
	void operator()(FILE *file)
	{
		if (file)
			std::fclose(file);
	}
};

struct VSScriptDelete {
	void operator()(VSScript *script) { VSScriptLibrary::get()->freeScript(script); }
};


int set_stderr_codepage()
{
#if defined(_WIN32) && defined(_UNICODE)
	return _setmode(_fileno(stderr), _O_U16TEXT) < 0;
#else
	return 0;
#endif
}

int set_stdout_binary()
{
#ifdef _WIN32
	return _setmode(_fileno(stdout), O_BINARY) < 0;
#else
	return std::freopen(nullptr, "wb", stdout) != stdout;
#endif
}

void install_ctrl_c_handler()
{
#ifdef _WIN32
	auto handler = [](DWORD dwCtrlType) -> BOOL
	{
		if (dwCtrlType == CTRL_C_EVENT || dwCtrlType == CTRL_BREAK_EVENT || dwCtrlType == CTRL_CLOSE_EVENT)
			std::exit(EXIT_FAILURE);
		return FALSE;
	};

	SetConsoleCtrlHandler(handler, TRUE);
#endif
}

void print_help()
{
	static const _TCHAR msg[] =
		_T("pipe_example usage:\n")
		_T("  pipe_example [options] <script> <outfile>\n")
		_T("Available options:\n")
		_T("  -a, --arg key=value           Argument to pass to the script environment\n")
		_T("  -s, --start N                 Set output frame range (first frame)\n")
		_T("  -e, --end N                   Set output frame range (last frame)\n")
		_T("  -o, --outputindex N           Select output index\n")
		_T("  -r, --requests N              Set number of concurrent frame requests\n")
		_T("  -c, --container <ym/wav/w64>  Add YUV4MPEG headers to output\n")
		_T("  -t, --timecodes FILE          Write timecodes v2 file\n")
		_T("  -p, --progress                Print progress to stderr\n")
		_T("      --filter-time             Prints time spent in individual filters after processing\n")
		_T("  -i, --info                    Show video info and exit\n")
		_T("  -g, --graph <simple/full>     Print output node filter graph in dot format and exit\n")
		_T("  -v, --version                 Show version info and exit\n")
		_T("\n")
		_T("Examples:\n")
		_T("  Show script info:\n")
		_T("    pipe_example --info script.vpy\n")
		_T("  Write to stdout:\n")
		_T("    pipe_example [options] script.vpy -\n")
		_T("  Request all frames but don't output them:\n")
		_T("    pipe_example [options] script.vpy .\n")
		_T("  Write frames 5-100 to file:\n")
		_T("    pipe_example --start 5 --end 100 script.vpy output.raw\n")
		_T("  Pass values to a script:\n")
		_T("    pipe_example --arg deinterlace=yes --arg \"message=fluffy kittens\" script.vpy output.raw\n")
		_T("  Pipe to x264 and write timecodes file:\n")
		_T("    pipe_example script.vpy - -c y4m --timecodes timecodes.txt | x264 --demuxer y4m -o script.mkv -\n");

	_fputts(msg, stderr);
}

void print_version()
{
	try {
		VSScriptLibrary::ensure();
		vsxx4::CoreInstance core = vsxx4::CoreInstance::create();
		_ftprintf(stdout, _T("%") FMT_S, core.core_info().versionString); // versionString ends in newline.
	} catch (const ScriptError &e) {
		_ftprintf(stderr, _T("%") FMT_S _T("\n"), e.what());
		std::exit(EXIT_FAILURE);
	}
}


std::string tstring_to_utf8(const tstring &tstr)
{
#if defined(_WIN32) && defined(_UNICODE)
	std::string s(std::min(static_cast<size_t>(INT_MAX) / 4, tstr.size()) * 4, '\0');
	size_t size;

	if (!(size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
		tstr.c_str(), static_cast<int>(tstr.size()), &s[0], static_cast<int>(s.size()),
		nullptr, nullptr)))
	{
		_ftprintf(stderr, _T("invalid unicode string: %") FMT_TS _T("\n"), tstr.c_str());
		throw ScriptError{ "failed to decode string" };
	}

	s.resize(size);
	return s;
#elif defined(_WIN32) && defined(_MBCS)
	std::wstring ws(std::min(static_cast<size_t>(INT_MAX) / 4, tstr.size()) * 4, L'\0');
	size_t size;

	if (!(size = MultiByteToWideChar(CP_THREAD_ACP, MB_ERR_INVALID_CHARS,
		tstr.c_str(), static_cast<int>(tstr.size()), &ws[0], static_cast<int>(ws.size()))))
	{
		_ftprintf(stderr, _T("invalid ANSI string: %") FMT_TS _T("\n"), tstr.c_str());
		throw ScriptError{ "failed to decode string" };
	}
	ws.resize(size);

	std::string s(std::min(static_cast<size_t>(INT_MAX) / 4, ws.size()) * 4, '\0');
	if (!(size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
		ws.c_str(), static_cast<int>(ws.size()), &s[0], static_cast<int>(s.size()),
		nullptr, nullptr)))
	{
		_ftprintf(stderr, _T("invalid unicode string: %") FMT_TS _T("\n"), tstr.c_str());
		throw ScriptError{ "failed to decode string" };
	}
	s.resize(size);

	return s;
#else
	return tstr;
#endif
}

const _TCHAR *cf_to_string(VSColorFamily cf)
{
	switch (cf) {
	case cfGray:
		return _T("Gray");
	case cfRGB:
		return _T("RGB");
	case cfYUV:
		return _T("YUV");
	default:
		return _T("");
	}
}

const _TCHAR *st_to_string(int st)
{
	switch (st) {
	case stInteger:
		return _T("Integer");
	case stFloat:
		return _T("Float");
	default:
		return _T("");
	}
}

std::unique_ptr<VSScript, VSScriptDelete> create_script(const Arguments &args)
{
	const VSSCRIPTAPI *vss = VSScriptLibrary::get();

	std::unique_ptr<VSScript, VSScriptDelete> script;

	vsxx4::CoreInstance core;
	if (args.perf_counters || args.reflection)
		core = vsxx4::CoreInstance::create(ccfEnableGraphInspection);

	script.reset(VSScriptLibrary::get()->createScript(core.release()));
	if (!script)
		throw ScriptError{ "failed to create script environment" };

	vsxx4::MapInstance args_map = vsxx4::MapInstance::create();
	for (const auto &e : args.script_args) {
		std::string key = tstring_to_utf8(e.first);
		std::string val = tstring_to_utf8(e.second);
		args_map.set_prop(key.c_str(), val, maAppend, dtUtf8);
	}
	if (vss->setVariables(script.get(), args_map.get()))
		throw ScriptError{ "failed to set script arguments" };

	return script;
}

void write_y4m_header(FILE *file, const VSVideoInfo &vi, int length)
{
	std::string y4m_format;

	if (vi.format.colorFamily == cfGray) {
		y4m_format = "mono";
		if (vi.format.bitsPerSample > 8)
			y4m_format += std::to_string(vi.format.bitsPerSample);
	} else if (vi.format.colorFamily == cfYUV) {
#define SUBSAMPLE(ssw, ssh) (((ssw) << 2) | (ssh))
		switch (SUBSAMPLE(vi.format.subSamplingW, vi.format.subSamplingH)) {
		case SUBSAMPLE(1, 1):
			y4m_format = "420";
			break;
		case SUBSAMPLE(1, 0):
			y4m_format = "422";
			break;
		case SUBSAMPLE(0, 0):
			y4m_format = "444";
			break;
		case SUBSAMPLE(2, 2):
			y4m_format = "410";
			break;
		case SUBSAMPLE(2, 0):
			y4m_format = "411";
			break;
		case SUBSAMPLE(0, 1):
			y4m_format = "440";
			break;
		default:
			throw ScriptError{ "no y4m identifier for color format" };
		}
#undef SUBSAMPLE

		if (vi.format.sampleType == stInteger && vi.format.bitsPerSample > 8) {
			y4m_format += 'p';
			y4m_format += std::to_string(vi.format.bitsPerSample);
		} else if (vi.format.sampleType == stFloat) {
			switch (vi.format.bitsPerSample) {
			case 16:
				y4m_format += 'h';
				break;
			case 32:
				y4m_format += 's';
				break;
			case 64:
				y4m_format += 'd';
				break;
			default:
				break;
			}
		}
	} else {
		throw ScriptError{ "no y4m identifier for color format" };
	}

	if (fprintf(file, "YUV4MPEG2 C%s W%d H%d F%" PRId64 ":%" PRId64 " Ip A0:0 XLENGTH=%d\n",
		y4m_format.c_str(), vi.width, vi.height, vi.fpsNum, vi.fpsDen, length) < 0)
	{
		_tperror(_T("failed to write output"));
		throw ScriptError{ "write failed" };
	}
}

struct WAVEFORMATEXTENSIBLE {
	uint8_t  wFormatTag[2];
	uint16_t nChannels;
	uint32_t nSamplesPerSec;
	uint32_t nAvgBytesPerSec;
	uint16_t nBlockAlign;
	uint16_t wBitsPerSample;
	uint16_t cbSize;
	uint16_t wValidBitsPerSample;
	uint32_t dwChannelMask;
	uint8_t  SubFormat[16];
};
static_assert(offsetof(WAVEFORMATEXTENSIBLE, wValidBitsPerSample) == sizeof(WAVEFORMATEXTENSIBLE) - 22, "wrong offset");

constexpr uint16_t le16(uint16_t x)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	return x;
#else
	return ((x >> 8) & 0x00FF) | ((x << 8) & 0xFF00);
#endif
}

constexpr uint32_t le32(uint32_t x)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	return x;
#else
	return ((x >> 24) & 0x000000FF) | ((x >> 8) & 0x0000FF00) | ((x << 8) & 0x00FF0000) | ((x << 24) & 0xFF000000);
#endif
}

constexpr uint64_t le64(uint64_t x)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	return x;
#else
	return static_cast<uint64_t>(le32(static_cast<uint32_t>(x >> 32))) |
		(static_cast<uint64_t>(le32(static_cast<uint32_t>(x))) << 32);
#endif
}

unsigned audio_bytes_per_sample(const VSAudioFormat &fmt) { return (fmt.bitsPerSample + 7) / 8; }

void init_wave_format_ex(WAVEFORMATEXTENSIBLE &ex, const VSAudioInfo &ai)
{
	if (ai.format.channelLayout & 0xFFFFFFFF00000000)
		throw ScriptError{ "Channel type can not be represented in WAVEFORMATEX" };

	ex.wFormatTag[0] = 0xFE; ex.wFormatTag[1] = 0xFF;
	ex.nChannels = le16(static_cast<uint16_t>(ai.format.numChannels));
	ex.nSamplesPerSec = le32(ai.sampleRate);
	ex.nAvgBytesPerSec = le32(audio_bytes_per_sample(ai.format) * ai.format.numChannels * ai.sampleRate);
	ex.wBitsPerSample = le16(static_cast<uint16_t>(audio_bytes_per_sample(ai.format) * 8));
	ex.cbSize = le16(22);
	ex.wValidBitsPerSample = le16(static_cast<uint16_t>(ai.format.bitsPerSample));
	ex.dwChannelMask = le32(static_cast<uint32_t>(ai.format.channelLayout));

	constexpr uint8_t pcm_guid[16] = { 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71 };
	constexpr uint8_t ieee_guid[16] = { 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x80, 0x00, 0x00, 0xAA, 0x00, 0x38, 0x9B, 0x71 };
	std::memcpy(ex.SubFormat, ai.format.sampleType == stFloat ? ieee_guid : pcm_guid, sizeof(pcm_guid));
}

uint64_t audio_data_size(const VSAudioInfo &ai)
{
	return static_cast<size_t>(audio_bytes_per_sample(ai.format)) * ai.format.numChannels * ai.numSamples;
}

void write_wave_header(FILE *file, const VSAudioInfo &ai)
{
	struct {
		uint8_t riff[4] = { 'R', 'I', 'F', 'F' };
		uint32_t riff_size = 0;
		uint8_t wave[4] = { 'W', 'A', 'V', 'E' };
		uint8_t fmt[4] = { 'f', 'm', 't', '.' };
		uint32_t fmt_size = le32(sizeof(WAVEFORMATEXTENSIBLE));
		WAVEFORMATEXTENSIBLE ex = {};
		uint8_t data[4] = { 'd', 'a', 't', 'a' };
		uint32_t data_size = 0;
	} wave;
	static_assert(sizeof(wave) == 68, "wrong header size");

	uint64_t sz = audio_data_size(ai);
	if (sz > UINT32_MAX - sizeof(wave))
		throw ScriptError{ "WAV file size is limited to 4 GB" };

	wave.riff_size = le32(static_cast<uint32_t>(sz - (sizeof(wave) - (sizeof(wave.riff) + sizeof(wave.riff_size)))));
	wave.data_size = le32(static_cast<uint32_t>(sz));

	init_wave_format_ex(wave.ex, ai);

	if (fwrite(&wave, sizeof(wave), 1, file) != 1)
		throw ScriptError{ "error writing WAV header" };
}

void write_wave64_header(FILE *file, const VSAudioInfo &ai)
{
	struct {
		uint8_t riff_guid[16] = { 0x72, 0x69, 0x66, 0x66, 0x2E, 0x91, 0xCF, 0x11, 0xA5, 0xD6, 0x28, 0xDB, 0x04, 0xC1, 0x00, 0x00 };
		uint64_t riff_size;
		uint8_t wave_guid[16] = { 0x77, 0x61, 0x76, 0x65, 0xF3, 0xAC, 0xD3, 0x11, 0x8C, 0xD1, 0x00, 0xC0, 0x4F, 0x8E, 0xDB, 0x8A };
		uint8_t fmt_guid[16] = { 0x66, 0x6D, 0x74, 0x20, 0xF3, 0xAC, 0xD3, 0x11, 0x8C, 0xD1, 0x00, 0xC0, 0x4F, 0x8E, 0xDB, 0x8A };
		uint64_t fmt_size = le64(sizeof(WAVEFORMATEXTENSIBLE) + sizeof(fmt_guid) + sizeof(fmt_size));
		WAVEFORMATEXTENSIBLE ex = {};
		uint8_t data_guid[16] = { 0x64, 0x61, 0x74, 0x61, 0xF3, 0xAC, 0xD3, 0x11, 0x8C, 0xD1, 0x00, 0xC0, 0x4F, 0x8E, 0xDB, 0x8A };
		uint64_t data_size;
	} wave64;
	static_assert(sizeof(wave64) == 128, "wrong header size");

	uint64_t sz = audio_data_size(ai);
	wave64.riff_size = le64(sz + sizeof(wave64));
	wave64.data_size = le64(sz + sizeof(wave64.data_guid) + sizeof(wave64.data_size));

	init_wave_format_ex(wave64.ex, ai);

	if (fwrite(&wave64, sizeof(wave64), 1, file) != 1)
		throw ScriptError{ "error writing W64 header" };
}

void write_timecodes_header(FILE *file)
{
	if (fputs("# timecode format v2\n", file) < 0) {
		_tperror(_T("failed to write timecodes"));
		throw ScriptError{ "write failed" };
	}
}

void write_all(const uint8_t *buf, FILE *file, size_t n)
{
	while (n) {
		size_t ret = std::fwrite(buf, 1, n, file);
		if (ret != n && std::ferror(file)) {
			_tperror(_T("failed to write output"));
			throw ScriptError{ "write failed" };
		}

		n -= ret;
		buf += ret;
	}
}

void write_video_frame(OutputMode mode, int n, const vsxx4::ConstFrame &frame, const vsxx4::ConstFrame &alpha, std::vector<uint8_t> &tmp, FILE *out_file)
{
	assert(mode == OutputMode::RAW || mode == OutputMode::Y4M);
	if (mode == OutputMode::Y4M && fputs("FRAME\n", out_file) < 0) {
		_tperror(_T("failed to write output"));
		throw ScriptError{ "write failed" };
	}

	const VSVideoFormat &format = frame.video_format();
	size_t size = 0;

	for (int p = 0; p < format.numPlanes; ++p) {
		size += static_cast<size_t>(frame.width(p)) * frame.height(p) * format.bytesPerSample;
	}
	if (alpha) {
		if (frame.width() != alpha.width() || frame.height() != alpha.height())
			throw ScriptError{ "alpha has incompatible dimensions" };
		if (!vsh::isSameVideoFormat(&frame.video_format(), &alpha.video_format()))
			throw ScriptError{ "alpha has incompatible video format" };

		size += static_cast<size_t>(alpha.width()) * alpha.height() * alpha.video_format().bytesPerSample;
	}

	tmp.reserve(size);
	tmp.clear();

	for (int p = 0; p < format.numPlanes; ++p) {
		static const int gbr_order[] = { 1, 2, 0 };
		int src_plane = format.colorFamily == cfRGB ? gbr_order[p] : p;

		const uint8_t *read_ptr = frame.read_ptr(src_plane);
		size_t width = frame.width(src_plane);
		size_t height = frame.height(src_plane);
		ptrdiff_t stride = frame.stride(src_plane);

		for (size_t i = 0; i < height; ++i) {
			tmp.insert(tmp.end(), read_ptr, read_ptr + width * format.bytesPerSample);
			read_ptr += stride;
		}
	}
	if (alpha) {
		const VSVideoFormat &alpha_format = alpha.video_format();

		const uint8_t *read_ptr = alpha.read_ptr();
		size_t width = alpha.width();
		size_t height = alpha.height();
		ptrdiff_t stride = alpha.stride();

		for (size_t i = 0; i < height; ++i) {
			tmp.insert(tmp.end(), read_ptr, read_ptr + width * alpha_format.bytesPerSample);
			read_ptr += stride;
		}
	}

	write_all(tmp.data(), out_file, size);
}

void write_audio_frame(const vsxx4::ConstFrame &frame, std::vector<uint8_t> &tmp, FILE *out_file)
{
	const VSAudioFormat &format = frame.audio_format();

	unsigned samples = frame.sample_length();
	unsigned channels = format.numChannels;
	unsigned bytes_per_sample = audio_bytes_per_sample(format);
	size_t size = static_cast<size_t>(samples) * bytes_per_sample * channels;
	const uint8_t *read_ptr = frame.read_ptr();

	if (tmp.size() < size)
		tmp.resize(size);

	auto swizzle_16b = [](unsigned n, unsigned channels, const uint8_t *read_ptr, uint8_t *out)
	{
		for (size_t i = 0; i < n; ++i) {
			for (size_t ch = 0; ch < channels; ++ch) {
				reinterpret_cast<uint16_t *>(out)[i * channels + ch] = le16(reinterpret_cast<const uint16_t *>(read_ptr)[ch * VS_AUDIO_FRAME_SAMPLES + i]);
			}
		}
	};
	auto swizzle_24b = [](unsigned n, unsigned channels, const uint8_t *read_ptr, uint8_t *out)
	{
		for (size_t i = 0; i < n; ++i) {
			for (size_t ch = 0; ch < channels; ++ch) {
				uint32_t x = le32(reinterpret_cast<const uint32_t *>(read_ptr)[ch * VS_AUDIO_FRAME_SAMPLES + i]);
				uint8_t *dst = out + (i * channels + ch) * 3;
				std::memcpy(dst, &x, 3);
			}
		}
	};
	auto swizzle_32b = [](unsigned n, unsigned channels, const uint8_t *read_ptr, uint8_t *out)
	{
		for (size_t i = 0; i < n; ++i) {
			for (size_t ch = 0; ch < channels; ++ch) {
				reinterpret_cast<uint32_t *>(out)[i * channels + ch] = le32(reinterpret_cast<const uint32_t *>(read_ptr)[ch * VS_AUDIO_FRAME_SAMPLES + i]);
			}
		}
	};

	if (bytes_per_sample == 2)
		swizzle_16b(samples, channels, read_ptr, tmp.data());
	else if (bytes_per_sample == 3)
		swizzle_24b(samples, channels, read_ptr, tmp.data());
	else if (bytes_per_sample == 4)
		swizzle_32b(samples, channels, read_ptr, tmp.data());
	else
		assert(false);

	uint8_t *buf = tmp.data();
	while (size) {
		size_t ret = std::fwrite(buf, 1, size, out_file);
		if (ret != size && std::ferror(out_file)) {
			_tperror(_T("failed to write output"));
			throw ScriptError{ "write failed" };
		}

		size -= ret;
		buf += ret;
	}

	write_all(tmp.data(), out_file, size);
}

void write_timecodes(int64_t *tc_num, int64_t *tc_den, int n, const vsxx4::ConstFrame &frame, FILE *tc_file)
{
	vsxx4::ConstMapRef props = frame.frame_props_ro();

	if (fprintf(tc_file, "%f\n", static_cast<double>(*tc_num) * 1000 / *tc_den) < 0) {
		_tperror(_T("failed to write timecodes"));
		throw ScriptError{ "write failed" };
	}

	try {
		int64_t dur_num = props.get_prop<int64_t>("_DurationNum");
		int64_t dur_den = props.get_prop<int64_t>("_DurationDen");

		if (dur_num <= 0 || dur_den <= 0) {
			_ftprintf(stderr, _T("bad duration %") _T(PRId64) _T("/%") _T(PRId64) _T(" at frame %d\n"),
				dur_num, dur_den, n);
			throw ScriptError{ "bad duration value" };
		}

		if (*tc_den == dur_den) {
			*tc_num += dur_num;
		} else {
			int64_t tmp = dur_den;
			dur_num *= *tc_den;
			dur_den *= *tc_den;
			*tc_num *= tmp;
			*tc_den *= tmp;

			*tc_num += dur_num;

			vsh::muldivRational(tc_num, tc_den, 1, 1);
		}
	} catch (const vsxx4::map::MapError &) {
		_ftprintf(stderr, _T("missing duration at frame %d\n"), n);
		throw ScriptError{ "missing duration" };
	}
}

void pipe_video(const Arguments &args, const vsxx4::Core &core, const vsxx4::FilterNode &node, bool has_alpha, FILE *out_file, FILE *tc_file)
{
	if (args.mode != OutputMode::RAW && args.mode != OutputMode::Y4M)
		throw ScriptError{ "can only output video as raw or Y4M" };
	if (has_alpha && args.mode == OutputMode::Y4M)
		throw ScriptError{ "Y4M does not support alpha" };

	const ::VSVideoInfo &vi = node.video_info();

	const int num_requests = args.num_requests <= 0 ? core.core_info().numThreads : args.num_requests;
	const int start_frame = static_cast<int>(args.start_frame_or_sample);
	const int end_frame = args.end_frame_or_sample < 0 ? vi.numFrames - 1 : static_cast<int>(args.end_frame_or_sample);

	if (end_frame < start_frame)
		throw ScriptError{ "invalid range of frames" };

	if (!vsh::isConstantVideoFormat(&vi))
		throw ScriptError{ "cannot output node with variable format" };

	if (start_frame > vi.numFrames || end_frame > vi.numFrames) {
		_ftprintf(stderr, _T("requested frame range [%") _T(PRId64) _T("-%") _T(PRId64) _T(") not in script(%d frames)\n"),
			args.start_frame_or_sample, args.end_frame_or_sample, vi.numFrames);
		throw ScriptError{ "invalid range of frames" };
	}

	if (out_file && args.mode == OutputMode::Y4M)
		write_y4m_header(out_file, vi, end_frame - start_frame);
	if (tc_file)
		write_timecodes_header(tc_file);

	std::mutex mutex;
	std::condition_variable cv;
	std::map<int, vsxx4::ConstFrame> queue;
	std::atomic_int active_requests{ 0 };
	std::atomic_int callback_lock{ 0 };
	std::atomic_bool error_flag{ false };

	std::exception_ptr eptr;
	std::mutex eptr_mutex;

	// Set a return value to trigger warning in case the callback exits without running the DONE macro.
	auto frame_done_callback = [&](vsxx4::ConstFrame frame, int n, const vsxx4::FilterNode &node, const char *error) -> int
	{
#define DONE() do { --active_requests; cv.notify_one(); --callback_lock; return 0; } while (0)
		++callback_lock;

		if (error_flag)
			DONE();

		if (!error) {
			try {
				std::lock_guard<std::mutex> lock{ mutex };
				queue[n] = std::move(frame);
			} catch (...) {
				std::lock_guard<std::mutex> lock{ eptr_mutex };
				eptr = std::current_exception();
				error_flag = true;
			}
		} else {
			_ftprintf(stderr, _T("frame %d failed: %") FMT_S _T("\n"), n, error);
			error_flag = true;
		}

		DONE();
#undef DONE
	};

	try {
		FpsCounter fps_counter;
		std::vector<uint8_t> tmp;

		int requested_cur = start_frame;
		int output_cur = start_frame;

		int64_t tc_num = 0;
		int64_t tc_den = 1;

		for (int i = 0; i < std::min(num_requests, end_frame - start_frame); ++i) {
			node.get_frame_async(requested_cur++, frame_done_callback);
			++active_requests;
		}

		while (!error_flag && output_cur <= end_frame) {
			std::unique_lock<std::mutex> lock{ mutex };

			while (!queue.empty() && queue.begin()->first == output_cur) {
				vsxx4::ConstFrame frame = std::move(queue.begin()->second);
				queue.erase(queue.begin());

				lock.unlock();

				if (out_file) {
					vsxx4::ConstFrame alpha_frame;
					if (has_alpha)
						alpha_frame = frame.frame_props_ro().get_prop<vsxx4::ConstFrame>("_Alpha");

					write_video_frame(args.mode, output_cur, frame, alpha_frame, tmp, out_file);
				}
				if (tc_file)
					write_timecodes(&tc_num, &tc_den, output_cur, frame, tc_file);

				if (args.progress) {
					double fps = fps_counter.update();

					if (std::isnan(fps))
						_ftprintf(stderr, _T("Frame: %d/%d\r"), output_cur - start_frame + 1, end_frame - start_frame + 1);
					else
						_ftprintf(stderr, _T("Frame: %d/%d (%.2f fps)\r"), output_cur - start_frame + 1, end_frame - start_frame + 1, fps);
				}

				++output_cur;

				if (requested_cur <= end_frame) {
					node.get_frame_async(requested_cur++, frame_done_callback);
					++active_requests;
				}

				lock.lock();
			}

			if (!error_flag && output_cur <= end_frame)
				cv.wait(lock);
		}
	} catch (...) {
		std::lock_guard<std::mutex> lock{ eptr_mutex };
		eptr = std::current_exception();
		error_flag = true;
	}

	// Wait for any requests to finish before exiting the stack frame.
	if (active_requests) {
		std::unique_lock<std::mutex> lock{ mutex };
		cv.wait(lock, [&]() { return !active_requests; });
	}
	// Handle the case where active_requests hits zero before the lock is acquired.
	while (callback_lock) {
		// ...
	}

	if (eptr)
		std::rethrow_exception(eptr);
	if (error_flag)
		throw ScriptError{ "piping failed" };
}

void pipe_audio(const Arguments &args, const vsxx4::Core &core, const vsxx4::FilterNode &node, FILE *out_file)
{
	if (args.mode != OutputMode::RAW && args.mode != OutputMode::WAVE && args.mode != OutputMode::WAVE64)
		throw ScriptError{ "can only output video as raw or Y4M" };

	const ::VSAudioInfo &ai = node.audio_info();
	const int num_requests = args.num_requests <= 0 ? core.core_info().numThreads : args.num_requests;
	const int64_t start_sample = args.start_frame_or_sample;
	const int64_t end_sample = args.end_frame_or_sample < 0 ? ai.numSamples - 1 : args.end_frame_or_sample;

	if (end_sample < start_sample)
		throw ScriptError{ "invalid range of samples" };

	if (start_sample > ai.numSamples || end_sample > ai.numSamples) {
		_ftprintf(stderr, _T("requested sample range [%") _T(PRId64) _T("-%") _T(PRId64) _T(") not in script(%") _T(PRId64) _T(" samples)\n"),
			args.start_frame_or_sample, args.end_frame_or_sample, ai.numSamples);
		throw ScriptError{ "invalid range of samples" };
	}

	vsxx4::MapInstance trim_args = vsxx4::MapInstance::create();
	trim_args.set_prop("clip", node);
	trim_args.set_prop("first", start_sample);
	trim_args.set_prop("last", end_sample);
	vsxx4::FilterNode trim_node = core.get_plugin_by_namespace("std").invoke("AudioTrim", trim_args).get_prop<vsxx4::FilterNode>("clip");
	const ::VSAudioInfo &trim_ai = trim_node.audio_info();

	if (args.mode == OutputMode::WAVE)
		write_wave_header(out_file, trim_ai);
	else if (args.mode == OutputMode::WAVE64)
		write_wave64_header(out_file, trim_ai);

	// Enable cache for prefetch.
	trim_node.set_cache_mode(1);

	// Do output.
	FpsCounter fps_counter;
	std::vector<uint8_t> tmp;

	// Bind nothing. Do nothing.
	auto prefetch_cb = [](vsxx4::ConstFrame, int, const vsxx4::FilterNode &, const char *) {};

	for (int n = 0; n < std::min(num_requests, trim_ai.numFrames); ++n) {
		trim_node.get_frame_async(n, prefetch_cb);
	}

	for (int n = 0; n < trim_ai.numFrames; ++n) {
		vsxx4::ConstFrame frame = trim_node.get_frame(n);
		if (trim_ai.numFrames - n > num_requests)
			trim_node.get_frame_async(n + num_requests, prefetch_cb);

		write_audio_frame(frame, tmp, out_file);

		if (args.progress) {
			double fps = fps_counter.update();

			if (std::isnan(fps)) {
				_ftprintf(stderr, _T("Sample: %") _T(PRId64) _T("/%") _T(PRId64) _T("\r"), static_cast<int64_t>(n) * VS_AUDIO_FRAME_SAMPLES, ai.numSamples);
			} else if (n % 100) {
				_ftprintf(stderr, _T("Sample: %") _T(PRId64) _T("/%") _T(PRId64) _T("(% .2f sps)\r"),
					static_cast<int64_t>(n) * VS_AUDIO_FRAME_SAMPLES, ai.numSamples, fps * VS_AUDIO_FRAME_SAMPLES);
			}
		}
	}
}

void print_vi(const VSVideoInfo &vi)
{
	if (vi.width && vi.height) {
		_ftprintf(stderr, _T("Width: %d\n"), vi.width);
		_ftprintf(stderr, _T("Height: %d\n"), vi.height);
	} else {
		_fputts(_T("Width: Variable\n"), stderr);
		_fputts(_T("Height: Variable\n"), stderr);
	}

	_ftprintf(stderr, _T("Frames: %d\n"), vi.numFrames);

	if (vi.fpsNum && vi.fpsDen) {
		_ftprintf(stderr, _T("FPS: %") _T(PRId64) _T("/%") _T(PRId64) _T(" (%.3f fps)\n"),
			vi.fpsNum, vi.fpsDen, static_cast<double>(vi.fpsNum) / vi.fpsDen);
	} else {
		_fputts(_T("FPS: Variable\n"), stderr);
	}

	if (vi.format.colorFamily != cfUndefined) {
		char name[32];
		int err = vsxx4::get_vsapi()->getVideoFormatName(&vi.format, name);
		assert(!err);

		_ftprintf(stderr, _T("Format Name: %") FMT_S _T("\n"), name);
		_ftprintf(stderr, _T("Color Family: %") FMT_TS _T("\n"), cf_to_string(static_cast<VSColorFamily>(vi.format.colorFamily)));
		_ftprintf(stderr, _T("Sample Type: %") FMT_TS _T("\n"), st_to_string(static_cast<VSSampleType>(vi.format.sampleType)));
		_ftprintf(stderr, _T("Bits: %d\n"), vi.format.bitsPerSample);
		_ftprintf(stderr, _T("SubSampling W: %d\n"), vi.format.subSamplingW);
		_ftprintf(stderr, _T("SubSampling H: %d\n"), vi.format.subSamplingH);
	} else {
		_fputts(_T("Format Name: Variable\n"), stderr);
	}
}

void print_ai(const VSAudioInfo &ai)
{
	char name[32];
	int err = vsxx4::get_vsapi()->getAudioFormatName(&ai.format, name);
	assert(!err);

	_ftprintf(stderr, _T("Samples: %" PRId64 "\n"), ai.numSamples);
	_ftprintf(stderr, _T("Sample Rate: %d\n"), ai.sampleRate);
	_ftprintf(stderr, _T("Format Name: %") FMT_S _T("\n"), name);
	_ftprintf(stderr, _T("Sample Type: %") FMT_TS _T("\n"), st_to_string(static_cast<VSSampleType>(ai.format.sampleType)));
	_ftprintf(stderr, _T("Bits: %d\n"), ai.format.bitsPerSample);
	_ftprintf(stderr, _T("Channels: %d\n"), ai.format.numChannels);
	_ftprintf(stderr, _T("Layout: %" PRIx64 "\n"), ai.format.channelLayout); // FIXME
}

void run_script(const Arguments &args, FILE *out_file, FILE *tc_file)
{
	const VSSCRIPTAPI *vss = VSScriptLibrary::get();

	// VSScript may change the console encoding.
	set_stderr_codepage();

	auto start_time = std::chrono::high_resolution_clock::now();
	auto script = create_script(args);

	if (vss->evaluateFile(script.get(), tstring_to_utf8(args.in_path).c_str())) {
		_ftprintf(stderr, _T("script evaluation failed: %") FMT_S _T("\n"), vss->getError(script.get()));
		throw ScriptError{ "failed to evaluate script" };
	}

	vsxx4::CoreRef core{ vss->getCore(script.get()) };
	assert(core);

	vsxx4::FilterNode node{ vss->getOutputNode(script.get(), args.out_idx) };
	if (!node) {
		_ftprintf(stderr, _T("invalid output index: %") FMT_S _T(" %d\n"), vss->getError(script.get()), args.out_idx);
		throw ScriptError{ "failed to get output" };
	}

	bool has_alpha = false;
	if (node.type() == mtVideo) {
		vsxx4::FilterNode alpha_node{ vss->getOutputAlphaNode(script.get(), args.out_idx) };
		if (alpha_node) {
			vsxx4::MapInstance args = vsxx4::MapInstance::create();
			args.set_prop("clip", std::move(node));
			args.set_prop("mclip", std::move(alpha_node));
			args.set_prop("prop", "_Alpha");

			node = core.get_plugin_by_namespace("std").invoke("PropToClip", args).get_prop<vsxx4::FilterNode>("clip");
			has_alpha = true;
		}
	}

	if (args.info) {
		if (node.type() == mtVideo)
			print_vi(node.video_info());
		else
			print_ai(node.audio_info());
		return;
	}
	if (args.reflection) {
		(void)0;// print_graph(node);
		return;
	}

	if (node.type() == mtVideo)
		pipe_video(args, core, node, has_alpha, out_file, tc_file);
	else
		pipe_audio(args, core, node, out_file);

	auto end_time = std::chrono::high_resolution_clock::now();

	int64_t num_frames_or_samples = node.type() == mtVideo ? node.video_info().numFrames : node.audio_info().numSamples;
	int64_t end_frame_or_sample = args.end_frame_or_sample < 0 ? num_frames_or_samples : args.end_frame_or_sample;
	double elapsed = std::chrono::duration_cast<std::chrono::duration<double>>(end_time - start_time).count();
	double fps_or_sps = (end_frame_or_sample - args.start_frame_or_sample) / elapsed;

	if (args.progress)
		_fputts(_T("\n"), stdout);

	if (node.type() == mtVideo)
		_ftprintf(stderr, _T("Output %" PRId64 " frames in %.2f seconds (%.2f fps)\n"), end_frame_or_sample - args.start_frame_or_sample + 1, elapsed, fps_or_sps);
	else
		_ftprintf(stderr, _T("Output %" PRId64 " samples in %.2f seconds (%.2f sample/s)\n"), end_frame_or_sample - args.start_frame_or_sample + 1, elapsed, fps_or_sps);

	if (args.perf_counters && vsxx4::get_vsapi()->getNodeFilterTime)
		(void)0;// print_perf_counters(node, alpha_node);
}

void run(const Arguments &args)
{
	std::unique_ptr<FILE, FileCloser> out_file;
	std::unique_ptr<FILE, FileCloser> tc_file;
	FILE *out_file_ptr = nullptr;

	if (args.in_path.empty())
		throw ScriptError{ "no script file specified" };
	if (!args.info && args.out_path.empty())
		throw ScriptError{ "no output file specified" };

	if (args.out_path == _T("-")) {
		if (set_stdout_binary()) {
			_tperror(_T("failed to set stdout to binary mode"));
			throw ScriptError{ "failed to open output file" };
		}
		out_file_ptr = stdout;
	} else if (!args.out_path.empty() && args.out_path != _T(".")) {
		out_file.reset(_tfopen(args.out_path.c_str(), _T("wb")));
		if (!out_file) {
			_tperror(args.out_path.c_str());
			throw ScriptError{ "failed to open output file" };
		}
		out_file_ptr = out_file.get();
	}

	if (!args.tc_path.empty()) {
		tc_file.reset(_tfopen(args.tc_path.c_str(), _T("w")));
		if (!tc_file) {
			_tperror(args.tc_path.c_str());
			throw ScriptError{ "failed to open timecodes file" };
		}
	}

	run_script(args, out_file_ptr, tc_file.get());
}

} // namespace


int _tmain(int argc, _TCHAR **argv)
{
	Arguments args{};

	install_ctrl_c_handler();

	try {
		bool have_in_path = false;
		bool have_out_path = false;

		for (int n = 1; n < argc; ++n) {
#define MATCH(x) (!_tcscmp(_T(x), arg))
			_TCHAR *arg = argv[n];

			auto require_next = [&]()
			{
				if (++n >= argc)
					throw BadCommandLine{};
			};
			auto parse_int = [&](int &out)
			{
				require_next();

				try {
					out = std::stoi(tstring(argv[n]));
				} catch (const std::invalid_argument &) {
					_ftprintf(stderr, _T("error parsing value as integer: %") FMT_TS _T("\n"), argv[n]);
					throw BadCommandLine{};
				} catch (const std::out_of_range &) {
					_ftprintf(stderr, _T("integer out of range: %") FMT_TS _T("\n"), argv[n]);
					throw BadCommandLine{};
				}
			};
			auto parse_int64 = [&](int64_t &out)
			{
				require_next();

				try {
					out = std::stoll(tstring(argv[n]));
				} catch (const std::invalid_argument &) {
					_ftprintf(stderr, _T("error parsing value as integer: %") FMT_TS _T("\n"), argv[n]);
					throw BadCommandLine{};
				} catch (const std::out_of_range &) {
					_ftprintf(stderr, _T("integer out of range: %") FMT_TS _T("\n"), argv[n]);
					throw BadCommandLine{};
				}
			};

			if (MATCH("-h") || MATCH("-?") || MATCH("--help")) {
				args.help = true;
				break;
			} else if (MATCH("-v") || MATCH("--version")) {
				args.version = true;
				break;
			} else if (MATCH("-a") || MATCH("--arg")) {
				tstring key;
				tstring value;
				size_t split_idx;

				require_next();

				key = argv[n];
				split_idx = key.find('=');

				if (split_idx == tstring::npos) {
					_ftprintf(stderr, _T("bad script argument: %") FMT_TS _T("\n"), argv[n]);
					throw BadCommandLine{};
				}

				value = key.substr(split_idx + 1);
				key = key.substr(0, split_idx);

				args.script_args.emplace(std::move(key), std::move(value));
			} else if (MATCH("-s") || MATCH("--start")) {
				parse_int64(args.start_frame_or_sample);
			} else if (MATCH("-e") || MATCH("--end")) {
				parse_int64(args.end_frame_or_sample);
			} else if (MATCH("-o") || MATCH("--outputindex")) {
				parse_int(args.out_idx);
			} else if (MATCH("-r") || MATCH("--requests")) {
				parse_int(args.num_requests);
			} else if (MATCH("-c") || MATCH("--container")) {
				require_next();

				if (!_tcscmp(_T("y4m"), argv[n])) {
					args.mode = OutputMode::Y4M;
				} else if (!_tcscmp(_T("wav"), argv[n])) {
					args.mode = OutputMode::WAVE;
				} else if (!_tcscmp(_T("w64"), argv[n])) {
					args.mode = OutputMode::WAVE64;
				} else {
					_ftprintf(stderr, _T("unknown parameter to --container: %") FMT_TS _T("\n"), argv[n]);
					throw BadCommandLine{};
				}
			} else if (MATCH("-t") || MATCH("--timecodes")) {
				require_next();
				args.tc_path = argv[n];
			} else if (MATCH("-p") || MATCH("--progress")) {
				args.progress = true;
			} else if (MATCH("--filter-time")) {
				args.perf_counters = true;
			} else if (MATCH("-i") || MATCH("--info")) {
				args.info = true;
			} else if (MATCH("-g") || MATCH("--graph")) {
				require_next();

				if (!_tcscmp(_T("simple"), argv[n])) {
					args.reflection = true;
					args.verbose_reflection = false;
				} else if (!_tcscmp(_T("full"), argv[n])) {
					args.reflection = true;
					args.verbose_reflection = true;
				} else {
					_ftprintf(stderr, _T("unknown parameter to --graph: %") FMT_TS _T("\n"), argv[n]);
					throw BadCommandLine{};
				}
			} else if (!have_in_path && *arg != _T('-')) {
				args.in_path = arg;
				have_in_path = true;
			} else if (!have_out_path && (MATCH("-") || *arg != _T('-'))) {
				args.out_path = arg;
				have_out_path = true;
			} else {
				_ftprintf(stderr, _T("unknown argument: %") FMT_TS _T("\n"), arg);
				throw BadCommandLine{};
			}
#undef MATCH
		}

		if (args.help) {
			print_help();
			return EXIT_SUCCESS;
		}
		if (args.version) {
			print_version();
			return EXIT_SUCCESS;
		}
	} catch (const BadCommandLine &) {
		print_help();
		return EXIT_FAILURE;
	} catch (const std::exception &e) {
		_ftprintf(stderr, _T("C++ exception: %") FMT_S _T("\n"), e.what());
		return EXIT_FAILURE;
	}

	try {
		run(args);
	} catch (const ScriptError &e) {
		_ftprintf(stderr, _T("%") FMT_S _T("\n"), e.what());
		return EXIT_FAILURE;
	} catch (const std::exception &e) {
		_ftprintf(stderr, _T("C++ exception: %") FMT_S _T("\n"), e.what());
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
