#include <algorithm>
#include <atomic>
#include <chrono>
#include <cinttypes>
#include <climits>
#include <cmath>
#include <condition_variable>
#include <cstdlib>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <map>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>

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
#else
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

#include <VSScript.h>
#include "VapourSynth++.hpp"

namespace {

typedef std::basic_string<_TCHAR> tstring;

struct BadCommandLine : public std::runtime_error {
	BadCommandLine() : std::runtime_error("") {}
};

struct ScriptError : public std::runtime_error {
	using std::runtime_error::runtime_error;
};

struct Arguments {
	tstring in_path;
	tstring out_path;
	tstring tc_path;
	std::unordered_map<tstring, tstring> script_args;
	int start_frame = 0;
	int end_frame = -1;
	int out_idx = 0;
	int num_requests = 0;
	bool help = false;
	bool info = false;
	bool progress = false;
	bool version = false;
	bool y4m = false;
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

class VSScriptGuard {
	static int s_count;
public:
	VSScriptGuard()
	{
		if (!s_count) {
			const ::VSAPI *vsapi;

			if (!vsscript_init())
				throw ScriptError{ "failed to initialize VapourSynth environment" };
			if (!(vsapi = vsscript_getVSApi()))
				throw ScriptError{ "failed to get VapourSynth API pointer" };

			vsxx::set_vsapi(vsapi);
			++s_count;
		}
	}

	VSScriptGuard(const VSScriptGuard &) = delete;

	~VSScriptGuard()
	{
		if (--s_count == 0) {
			vsxx::set_vsapi(nullptr);
			vsscript_finalize();
		}
	}

	VSScriptGuard &operator=(const VSScriptGuard &) = delete;
};

int VSScriptGuard::s_count;

struct FileCloser{
	void operator()(::FILE *file)
	{
		if (file)
			std::fclose(file);
	}
};

struct VSScriptDelete {
	void operator()(::VSScript *script) { vsscript_freeScript(script); }
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
		_T("  -a, --arg key=value   Argument to pass to the script environment\n")
		_T("  -s, --start N         Set output frame range (first frame)\n")
		_T("  -e, --end N           Set output frame range (last frame)\n")
		_T("  -o, --outputindex N   Select output index\n")
		_T("  -r, --requests N      Set number of concurrent frame requests\n")
		_T("  -y, --y4m             Add YUV4MPEG headers to output\n")
		_T("  -t, --timecodes FILE  Write timecodes v2 file\n")
		_T("  -p, --progress        Print progress to stderr\n")
		_T("  -i, --info            Show video info and exit\n")
		_T("  -v, --version         Show version info and exit\n")
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
		_T("    pipe_example script.vpy - --y4m --timecodes timecodes.txt | x264 --demuxer y4m -o script.mkv -\n");

	_fputts(msg, stderr);
}

void print_version()
{
	try {
		VSScriptGuard vss;
		vsxx::VapourCoreOwner core = vsxx::VapourCoreOwner::create(1);
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

const _TCHAR *cf_to_string(int cf)
{
	switch (cf) {
	case cmGray:
		return _T("Gray");
	case cmRGB:
		return _T("RGB");
	case cmYUV:
		return _T("YUV");
	case cmYCoCg:
		return _T("YCoCg");
	case cmCompat:
		return _T("Compat");
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

std::unique_ptr<::VSScript, VSScriptDelete> create_script(const Arguments &args)
{
	std::unique_ptr<::VSScript, VSScriptDelete> script;
	::VSScript *script_ptr;

	if (vsscript_createScript(&script_ptr))
		throw ScriptError{ "failed to create script environment" };

	script.reset(script_ptr);

	vsxx::PropertyMapOwner args_map = vsxx::PropertyMapOwner::create();
	for (const auto &e : args.script_args) {
		std::string key = tstring_to_utf8(e.first);
		std::string val = tstring_to_utf8(e.second);
		args_map.set_prop(key.c_str(), val, paAppend);
	}

	if (vsscript_setVariable(script.get(), args_map.get()))
		throw ScriptError{ "failed to set script arguments" };

	return script;
}

void write_y4m_header(FILE *file, const ::VSVideoInfo &vi)
{
	std::string y4m_format;

	if (vi.format->colorFamily == cmGray) {
		y4m_format = "mono";
		if (vi.format->bitsPerSample > 8)
			y4m_format += std::to_string(vi.format->bitsPerSample);
	} else if (vi.format->colorFamily == cmYUV) {
#define SUBSAMPLE(ssw, ssh) (((ssw) << 2) | (ssh))
		switch (SUBSAMPLE(vi.format->subSamplingW, vi.format->subSamplingH)) {
		case SUBSAMPLE(1, 1):
			y4m_format = "420";
			break;
		case SUBSAMPLE(1, 0):
			y4m_format = "422";
			break;
		case SUBSAMPLE(0, 0):
			y4m_format = "420";
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

		if (vi.format->sampleType == stInteger && vi.format->bitsPerSample > 8) {
			y4m_format += 'p';
			y4m_format += std::to_string(vi.format->bitsPerSample);
		} else if (vi.format->sampleType == stFloat) {
			switch (vi.format->bitsPerSample) {
			case 16:
				y4m_format += 'h';
			case 32:
				y4m_format += 's';
			case 64:
				y4m_format += 'd';
			default:
				break;
			}
		}
	} else {
		throw ScriptError{ "no y4m identifier for color format" };
	}

	if (fprintf(file, "YUV4MPEG2 C%s W%d H%d F%" PRId64 ":%" PRId64 " Ip A0:0 XLENGTH=%d\n",
	            y4m_format.c_str(), vi.width, vi.height, vi.fpsNum, vi.fpsDen, vi.numFrames) < 0)
	{
		_tperror(_T("failed to write output"));
		throw ScriptError{ "write failed" };
	}
}

void write_tc_header(FILE *file)
{
	if (fputs("# timecode format v2\n", file) < 0) {
		_tperror(_T("failed to write timecodes"));
		throw ScriptError{ "write failed" };
	}
}

void write_frame(const Arguments &args, int64_t *tc_num, int64_t *tc_den, int n, const vsxx::ConstVideoFrame &frame, FILE *out_file, FILE *tc_file)
{
	static const int gbr_order[] = { 1, 2, 0 };

	if (out_file) {
		const ::VSFormat &format = frame.format();

		if (args.y4m && fputs("FRAME\n", out_file) < 0) {
			_tperror(_T("failed to write output"));
			throw ScriptError{ "write failed" };
		}

		for (int p = 0; p < format.numPlanes; ++p) {
			int src_plane = format.colorFamily == cmRGB ? gbr_order[p] : p;

			const uint8_t *read_ptr = frame.read_ptr(src_plane);
			int width = frame.width(src_plane);
			int height = frame.height(src_plane);
			int stride = frame.stride(src_plane);

			for (int i = 0; i < height; ++i) {
				const uint8_t *buf = read_ptr;
				size_t n = width * format.bytesPerSample;

				while (n) {
					size_t ret = std::fwrite(buf, 1, n, out_file);
					if (ret != n && std::ferror(out_file)) {
						_tperror(_T("failed to write output"));
						throw ScriptError{ "write failed" };
					}
					buf += ret;
					n -= ret;
				}

				read_ptr += stride;
			}
		}
	}
	if (tc_file) {
		vsxx::ConstPropertyMapRef props = frame.frame_props_ro();

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

				muldivRational(tc_num, tc_den, 1, 1);
			}
		} catch (const vsxx::map::MapGetError &) {
			_ftprintf(stderr, _T("missing duration at frame %d\n"), n);
			throw ScriptError{ "missing duration" };
		}

	}
}

void pipe_script(const Arguments &args, const vsxx::VapourCore &core, const vsxx::FilterNode &node, FILE *out_file, FILE *tc_file)
{
	const ::VSVideoInfo &vi = node.video_info();

	const int num_requests = args.num_requests <= 0 ? core.core_info()->numThreads : args.num_requests;
	const int start_frame = args.start_frame;
	const int end_frame = args.end_frame < 0 ? node.video_info().numFrames : args.end_frame;

	if (!isConstantFormat(&vi))
		throw ScriptError{ "cannot output node with variable format" };

	if (start_frame > vi.numFrames || end_frame > vi.numFrames) {
		_ftprintf(stderr, _T("requested frame range [%d-%d) not in script (%d frames)\n"),
		          args.start_frame, args.end_frame, vi.numFrames);
		throw ScriptError{ "invalid range of frames" };
	}

	if (out_file && args.y4m)
		write_y4m_header(out_file, vi);
	if (tc_file)
		write_tc_header(tc_file);

	std::mutex mutex;
	std::condition_variable cv;
	std::map<int, vsxx::ConstVideoFrame> queue;
	std::atomic_int active_requests = 0;
	std::atomic_bool error_flag = false;

	std::exception_ptr eptr;
	std::mutex eptr_mutex;

	auto frame_done_callback = [&](vsxx::ConstVideoFrame frame, int n, const vsxx::FilterNode &node, const char *error)
	{
		--active_requests;

		if (error_flag) {
			cv.notify_one();
			return;
		}

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

		cv.notify_one();
	};

	try {
		FpsCounter fps_counter;

		int requested_cur = start_frame;
		int output_cur = start_frame;

		int64_t tc_num = 0;
		int64_t tc_den = 1;

		for (int i = 0; i < std::min(num_requests, end_frame - start_frame); ++i) {
			node.get_frame_async(requested_cur++, frame_done_callback);
			++active_requests;
		}

		while (!error_flag && output_cur < end_frame) {
			std::unique_lock<std::mutex> lock{ mutex };

			while (!queue.empty() && queue.begin()->first == output_cur) {
				vsxx::ConstVideoFrame frame = std::move(queue.begin()->second);
				queue.erase(queue.begin());

				lock.unlock();

				write_frame(args, &tc_num, &tc_den, output_cur, frame, out_file, tc_file);

				if (args.progress) {
					double fps = fps_counter.update();

					if (std::isnan(fps))
						_ftprintf(stderr, _T("Frame: %d/%d\r"), output_cur - start_frame + 1, end_frame - start_frame);
					else
						_ftprintf(stderr, _T("Frame: %d/%d (%.2f fps)\r"), output_cur - start_frame, end_frame - start_frame, fps);
				}

				++output_cur;

				if (requested_cur < end_frame) {
					node.get_frame_async(requested_cur++, frame_done_callback);
					++active_requests;
				}

				lock.lock();
			}

			if (!error_flag && output_cur < end_frame)
				cv.wait(lock);
		}
	} catch (...) {
		std::lock_guard<std::mutex> lock{ eptr_mutex };
		eptr = std::current_exception();
		error_flag = true;
	}

	if (active_requests) {
		std::unique_lock<std::mutex> lock{ mutex };
		cv.wait(lock, [&]() { return !active_requests; });
	}

	if (eptr)
		std::rethrow_exception(eptr);
	if (error_flag)
		throw ScriptError{ "piping failed" };
}

void run_script(const Arguments &args, FILE *out_file, FILE *tc_file)
{
	VSScriptGuard vss;

	// VSScript may change the console encoding.
	set_stderr_codepage();

	auto script = create_script(args);

	auto start_time = std::chrono::high_resolution_clock::now();
	{
		::VSScript *script_ptr = script.get();
		int eval_err = vsscript_evaluateFile(&script_ptr, tstring_to_utf8(args.in_path).c_str(), efSetWorkingDir);

		// Ensure the right pointer is tracked in case VSScript reset the script context.
		script.release();
		script.reset(script_ptr);

		if (eval_err) {
			script.release();
			script.reset(script_ptr);
			_ftprintf(stderr, _T("script evaluation failed: %") FMT_S _T("\n"), vsscript_getError(script_ptr));
			throw ScriptError{ "failed to evaluate script" };
		}
	}

	vsxx::FilterNode node{ vsscript_getOutput(script.get(), args.out_idx) };
	if (!node) {
		_ftprintf(stderr, _T("invalid output index: %") FMT_S _T(" %d\n"), vsscript_getError(script.get()), args.out_idx);
		throw ScriptError{ "failed to get output" };
	}

	if (args.info) {
		const ::VSVideoInfo &vi = node.video_info();

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

		if (vi.format) {
			_ftprintf(stderr, _T("Format Name: %") FMT_S _T("\n"), vi.format->name);
			_ftprintf(stderr, _T("Color Family: %") FMT_TS _T("\n"), cf_to_string(vi.format->colorFamily));
			_ftprintf(stderr, _T("Sample Type: %") FMT_TS _T("\n"), st_to_string(vi.format->sampleType));
			_ftprintf(stderr, _T("Bits: %d\n"), vi.format->bitsPerSample);
			_ftprintf(stderr, _T("SubSampling W: %d\n"), vi.format->subSamplingW);
			_ftprintf(stderr, _T("SubSampling H: %d\n"), vi.format->subSamplingH);
		} else {
			_fputts(_T("Format Name: Variable\n"), stderr);
		}

		return;
	} else {
		pipe_script(args, vsxx::VapourCoreRef{ vsscript_getCore(script.get()) }, node, out_file, tc_file);
	}

	auto end_time = std::chrono::high_resolution_clock::now();

	const ::VSVideoInfo &vi = node.video_info();
	int end_frame = args.end_frame < 0 ? vi.numFrames : args.end_frame;
	double elapsed = std::chrono::duration_cast<std::chrono::duration<double>>(end_time - start_time).count();
	double fps = (end_frame - args.start_frame) / elapsed;

	if (args.progress)
		_fputts(_T("\n"), stdout);

	_ftprintf(stderr, _T("Output %d frames in %.2f seconds (%.2f fps)\n"), end_frame - args.start_frame, elapsed, fps);
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

			if (MATCH("-?") || MATCH("--help")) {
				args.help = true;
				break;
			} else if (MATCH("-v") || MATCH("--version")) {
				args.version = true;
				break;
			} else if (MATCH("-i") || MATCH("--info")) {
				args.info = true;
			} else if (MATCH("-p") || MATCH("--progress")) {
				args.progress = true;
			} else if (MATCH("-y") || MATCH("--y4m")) {
				args.y4m = true;
			} else if (MATCH("-s") || MATCH("--start")) {
				parse_int(args.start_frame);
			} else if (MATCH("-e") || MATCH("--end")) {
				parse_int(args.end_frame);
			} else if (MATCH("-o") || MATCH("--outputindex")) {
				parse_int(args.out_idx);
			} else if (MATCH("-r") || MATCH("--requests")) {
				parse_int(args.num_requests);
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

				args.script_args[std::move(key)] = std::move(value);
			} else if (MATCH("-t") || MATCH("--timecodes")) {
				require_next();
				args.tc_path = argv[n];
			} else if (!have_in_path && *arg != _T('-')) {
				args.in_path = arg;
				have_in_path = true;
			} else if (!have_out_path && *arg != _T('-')) {
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
