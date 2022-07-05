#ifndef VAPOURSYNTH4XX_HPP_
#define VAPOURSYNTH4XX_HPP_

#ifndef VSXX4_NAMESPACE
#define VSXX4_NAMESPACE vsxx4
#endif // VSXX4_NAMESPACE

#include <atomic>
#include <cassert>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <exception>
#include <functional>
#include <limits>
#include <memory>
#include <new>
#include <stdexcept>
#include <string>
#include <tuple>
#include <type_traits>
#include <utility>
#include <vector>

#if __cplusplus >= 201703L || _MSVC_LANG >= 201703L
#include <string_view>
#endif

#include "VapourSynth4.h"

namespace VSXX4_NAMESPACE {

namespace detail {

inline const ::VSAPI *vsapi(bool set = false, const ::VSAPI *ptr = nullptr)
{
	static const ::VSAPI *vsapi = nullptr;

	if (set)
		vsapi = ptr;

	return vsapi;
}

} // namespace detail


// Get stored VSAPI.
inline const VSAPI *get_vsapi() noexcept
{
	return detail::vsapi();
}

// Set VSAPI.
inline void set_vsapi(const VSAPI *vsapi) noexcept
{
	detail::vsapi(true, vsapi);
}


// Forward declaration of types that can be stored in VSMap.
class FrameRef;
class ConstFrameRef;

class Frame;
class ConstFrame;

class FilterNode;

class FilterFunction;


// Policy classes for VSMap getters.
namespace map {

struct MapError : public std::runtime_error {
	using std::runtime_error::runtime_error;
};

// peUnset
struct UnsetError : public MapError {
	using MapError::MapError;
};

// peType
struct TypeError : public MapError {
	using MapError::MapError;
};

// peIndex
struct IndexError : public MapError {
	using MapError::MapError;
};

// peError
struct InvalidStateError : public MapError {
	using MapError::MapError;
};

// From mapSetX.
struct AppendError : public MapError {
	using MapError::MapError;
};

template <class T>
class Default {
	T m_value;
public:
	explicit Default(const T &value) noexcept : m_value{ value } {}

	const T &operator()(const T &, const char *, ::VSMapPropertyError) noexcept { return m_value; }
};

struct Ignore {
	template <class T>
	T operator()(const T &, const char *, ::VSMapPropertyError) noexcept { return T{}; }
};

struct Throw {
	template <class T>
	const T &operator()(const T &x, const char *key, ::VSMapPropertyError error)
	{
		switch (error) {
		case peUnset:
			throw UnsetError{ key };
		case peType:
			throw TypeError{ key };
		case peError:
			throw InvalidStateError{ key };
		case peIndex:
			throw IndexError{ key };
		default:
			throw std::logic_error{ "unknown error" };
		}
	}
};

template <class T>
Default<typename std::decay<const T>::type> default_val(const T &val)
{
	return Default<typename std::decay<const T>::type>{ val };
}

inline Default<std::string> default_str(const std::string &s)
{
	return Default<std::string>{ s };
}


namespace detail {

template <class T, std::enable_if_t<std::is_signed<T>::value> * = nullptr>
bool overflows(int64_t val)
{
	return val > std::numeric_limits<T>::max() || val < std::numeric_limits<T>::min();
}

template <class T, std::enable_if_t<!std::is_signed<T>::value> * = nullptr>
bool overflows(int64_t val)
{
	return val < 0 || static_cast<uint64_t>(val) > std::numeric_limits<T>::max();
}

template <class T, std::enable_if_t<std::is_signed<T>::value> * = nullptr>
T saturate_int(int64_t val)
{
	return val > std::numeric_limits<T>::max() ? std::numeric_limits<T>::max() : val < std::numeric_limits<T>::min() ? std::numeric_limits<T>::min() : static_cast<T>(val);
}

template <class T, std::enable_if_t<!std::is_signed<T>::value> * = nullptr>
T saturate_int(int64_t val)
{
	return val < 0 ? static_cast<T>(0) : static_cast<uint64_t>(val) > std::numeric_limits<T>::max() ? std::numeric_limits<T>::max() : static_cast<T>(val);
}

template <>
inline bool saturate_int(int64_t val)
{
	return !!val;
}

template <class T, std::enable_if_t<std::is_integral<T>::value> * = nullptr>
T get_prop(const ::VSMap *map, const char *key, int index, int *error)
{
	int64_t val = get_vsapi()->mapGetInt(map, key, index, error);
	if (map::detail::overflows<T>(val))
		*error = peType;
	return *error ? T{} : static_cast<T>(val);
}

template <>
inline bool get_prop(const ::VSMap *map, const char *key, int index, int *error)
{
	return !!get_prop<int64_t>(map, key, index, error);
}

template <class T, std::enable_if_t<std::is_floating_point<T>::value> * = nullptr>
T get_prop(const ::VSMap *map, const char *key, int index, int *error)
{
	return static_cast<T>(get_vsapi()->mapGetFloat(map, key, index, error));
}

template <class T, std::enable_if_t<std::is_convertible<T, std::string>::value> * = nullptr>
T get_prop(const ::VSMap *map, const char *key, int index, int *error)
{
	const char *str = get_vsapi()->mapGetData(map, key, index, error);
	if (*error)
		return "";

	int len = get_vsapi()->mapGetDataSize(map, key, index, error);
	assert(len >= 0);
	if (*error)
		return "";

	return{ str, static_cast<size_t>(len) };
}

template <>
inline const char *get_prop(const ::VSMap *map, const char *key, int index, int *error)
{
	return get_vsapi()->mapGetData(map, key, index, error);
}

template <class T, std::enable_if_t<std::is_same<T, FilterNode>::value> * = nullptr>
T get_prop(const ::VSMap *map, const char *key, int index, int *error);

template <class T, std::enable_if_t<std::is_same<T, ConstFrame>::value> * = nullptr>
T get_prop(const ::VSMap *map, const char *key, int index, int *error);

template <class T, std::enable_if_t<std::is_same<T, FilterFunction>::value> * = nullptr>
T get_prop(const ::VSMap *map, const char *key, int index, int *error);


template <class T, std::enable_if_t<std::is_integral<T>::value> * = nullptr>
int set_prop(::VSMap *map, const char *key, const T &val, ::VSMapAppendMode append)
{
	if (std::is_unsigned<T>::value && static_cast<std::make_unsigned_t<T>>(val) > static_cast<uint64_t>(INT64_MAX))
		return 1;
	return get_vsapi()->mapSetInt(map, key, static_cast<int64_t>(val), append);
}

template <class T, std::enable_if_t<std::is_floating_point<T>::value> * = nullptr>
int set_prop(::VSMap *map, const char *key, const T &val, ::VSMapAppendMode append)
{
	return get_vsapi()->mapSetFloat(map, key, val, append);
}

int set_prop(::VSMap *map, const char *key, const FilterNode &val, ::VSMapAppendMode append);

int set_prop(::VSMap *map, const char *key, const ConstFrameRef &val, ::VSMapAppendMode append);

int set_prop(::VSMap *map, const char *key, const FilterFunction &val, ::VSMapAppendMode append);

inline int set_string_prop(::VSMap *map, const char *key, const char *val, ::VSDataTypeHint hint, ::VSMapAppendMode append)
{
	size_t len = std::strlen(val);
	if (len > INT_MAX)
		return 1;
	return get_vsapi()->mapSetData(map, key, val, static_cast<int>(len), hint, append);
}

#if __cplusplus >= 201703L || _MSVC_LANG >= 201703L
inline int set_string_prop(::VSMap *map, const char *key, std::string_view val, ::VSDataTypeHint hint, ::VSMapAppendMode append)
{
	if (val.size() > INT_MAX)
		return 1;
	return get_vsapi()->mapSetData(map, key, val.data(), static_cast<int>(val.size()), hint, append);
}
#endif

inline int set_string_prop(::VSMap *map, const char *key, const std::string &val, ::VSDataTypeHint hint, ::VSMapAppendMode append)
{
	if (val.size() > INT_MAX)
		return 1;
	return get_vsapi()->mapSetData(map, key, val.c_str(), static_cast<int>(val.size()), hint, append);
}


int consume_prop(::VSMap *map, const char *key, const FilterNode &val, ::VSMapAppendMode append);

int consume_prop(::VSMap *map, const char *key, const ConstFrameRef &val, ::VSMapAppendMode append);

int consume_prop(::VSMap *map, const char *key, const FilterFunction &val, ::VSMapAppendMode append);

} // namespace detail

} // namespace map


// VSMap reader methods.
class ConstMap {
	const ::VSMap *m_map;
protected:
	explicit ConstMap(const ::VSMap *map) noexcept : m_map{ map } {}
	ConstMap(const ConstMap &other) = default;

	~ConstMap() = default;

	ConstMap &operator=(const ConstMap &other) = default;

	void set(const ::VSMap *map) noexcept { m_map = map; }
public:
	explicit operator bool() const noexcept { return !!get(); }
	const ::VSMap *get() const noexcept { return m_map; }

	// VSAPI::mapGetError
	const char *get_error() const noexcept { return get_vsapi()->mapGetError(get()); }

	// VSAPI::mapNumKeys
	size_t size() const noexcept
	{
		int ret = get_vsapi()->mapNumKeys(get());
		assert(ret >= 0);
		return ret;
	}

	// VSAPI::mapGetKey.
	const char *get_key(size_t index) const noexcept
	{
		assert(index <= INT_MAX);
		return get_vsapi()->mapGetKey(get(), static_cast<int>(index));
	}

	// VSAPI::mapGetType
	int get_type(const char *key) const noexcept
	{
		return get_vsapi()->mapGetType(get(), key);
	}

	// VSAPI::mapNumElements.
	bool contains(const char *key) const noexcept
	{
		return get_vsapi()->mapNumElements(get(), key) >= 0;
	}

	size_t num_elements(const char *key) const
	{
		int ret = get_vsapi()->mapNumElements(get(), key);
		if (ret < 0)
			throw map::UnsetError{ key };
		return ret;
	}

	// VSAPI::mapGetX
	template <class T, class ErrorPolicy = map::Throw, std::enable_if_t<!std::is_convertible<ErrorPolicy, size_t>::value> * = nullptr>
	T get_prop(const char *key, ErrorPolicy error_policy = ErrorPolicy{}) const
	{
		return get_prop<T>(key, 0, error_policy);
	}

	template <class T, class ErrorPolicy = map::Throw>
	T get_prop(const char *key, size_t index, ErrorPolicy error_policy = ErrorPolicy{}) const
	{
		int error = 0;
		T ret = T{};

		if (index >= INT_MAX)
			error = ::peIndex;
		else
			ret = map::detail::get_prop<T>(get(), key, static_cast<int>(index), &error);

		if (error)
			return error_policy(ret, key, static_cast<::VSMapPropertyError>(error));

		return ret;
	}

	template <class T, class ErrorPolicy = map::Throw, std::enable_if_t<!std::is_convertible<ErrorPolicy, size_t>::value> * = nullptr>
	T get_prop_sat(const char *key, ErrorPolicy error_policy = ErrorPolicy{}) const
	{
		return get_prop_sat<T>(key, 0, error_policy);
	}

	template <class T, class ErrorPolicy = map::Throw, class U = T>
	std::enable_if_t<std::is_floating_point<T>::value, T> get_prop_sat(const char *key, size_t index, ErrorPolicy error_policy = ErrorPolicy{}) const
	{
		return get_prop<T>(key, index, error_policy);
	}

	template <class T, class ErrorPolicy = map::Throw, class U = T>
	std::enable_if_t<std::is_integral<T>::value, T> get_prop_sat(const char *key, size_t index, ErrorPolicy error_policy = ErrorPolicy{}) const
	{
		return map::detail::saturate_int<T>(get_prop<int64_t>(key, index, error_policy));
	}

	// VSAPI::mapGetXArray
	template <class T, class ErrorPolicy>
	const T *get_prop_array(const char *key, ErrorPolicy error_policy = ErrorPolicy{}) const
	{
		int error = 0;

		const T *ret = nullptr;
		if (error)
			return error_policy(ret, key, static_cast<::VSMapPropertyError>(error));

		return ret;
	}

	// VSAPI::mapGetDataTypeHint
	template <class T, class ErrorPolicy, std::enable_if_t<!std::is_convertible<ErrorPolicy, size_t>::value> * = nullptr>
	::VSDataTypeHint get_data_type_hint(const char *key, ErrorPolicy error_policy = ErrorPolicy{}) const
	{
		return get_data_type_hint<T>(key, 0, error_policy);
	}

	template <class ErrorPolicy>
	::VSDataTypeHint get_data_type_hint(const char *key, size_t index, ErrorPolicy error_policy = ErrorPolicy{}) const noexcept
	{
		int error = 0;

		::VSDataTypeHint ret = static_cast<::VSDataTypeHint>(get_vsapi()->mapGetDataTypeHint(get(), key, index, &error));
		if (error)
			return error_policy(ret, key, static_cast<::VSMapPropertyError>(error));

		return ret;
	}
};


// VSMap writer methods.
class Map : public ConstMap {
	template <class T>
	void do_consume_prop(const char *key, T &&val, ::VSMapAppendMode append) const
	{
		int ret = map::detail::consume_prop(get(), key, val, append);
		val.release();
		if (ret)
			throw map::AppendError{ key };
	}
protected:
	explicit Map(::VSMap *map) : ConstMap(map) {}
	Map(const Map &other) = default;

	~Map() = default;

	Map &operator=(const Map &other) = default;
public:
	::VSMap *get() const noexcept { return const_cast<::VSMap *>(ConstMap::get()); }

	void clear() { get_vsapi()->clearMap(get()); }

	// VSAPI::copyMap
	void copy_from(const ConstMap &other) const noexcept { get_vsapi()->copyMap(other.get(), get()); }

	// VSAPI::mapSetError
	void set_error(const char *error_message) const noexcept { get_vsapi()->mapSetError(get(), error_message); }

	void set_error(const std::string &error_message) const noexcept { get_vsapi()->mapSetError(get(), error_message.c_str()); }

	// VSAPI::mapDeleteKey
	void erase(const char *key) const noexcept { get_vsapi()->mapDeleteKey(get(), key); }

	// VSAPI::mapSetEmpty
	void set_empty_key(const char *key, int type) const
	{
		int ret = get_vsapi()->mapSetEmpty(get(), key, type);
		if (ret)
			throw map::AppendError{ key };
	}

	// VSAPI::mapSetX
	template <class T, std::enable_if_t<!std::is_convertible<T, std::string>::value> * = nullptr>
	void set_prop(const char *key, const T &val, ::VSMapAppendMode append = ::maReplace) const
	{
		if (map::detail::set_prop(get(), key, val, append))
			throw map::AppendError{ key };
	}

	template <class T, std::enable_if_t<std::is_convertible<T, std::string>::value> * = nullptr>
	void set_prop(const char *key, const T &val, ::VSMapAppendMode append = ::maReplace, ::VSDataTypeHint hint = ::dtUnknown) const
	{
		if (map::detail::set_string_prop(get(), key, val, hint, append))
			throw map::AppendError{ key };
	}

	// VSAPI::mapSetXArray
	void set_array(const char *key, const int64_t *arr, size_t count) const
	{
		if (count > INT_MAX || get_vsapi()->mapSetIntArray(get(), key, arr, static_cast<int>(count)))
			throw map::AppendError{ key };
	}

	void set_array(const char *key, const double *arr, size_t count) const
	{
		if (count > INT_MAX || get_vsapi()->mapSetFloatArray(get(), key, arr, static_cast<int>(count)))
			throw map::AppendError{ key };
	}

	// VSAPI::mapConsumeX
	void set_prop(const char *key, ConstFrame &&val, ::VSMapAppendMode append = ::maReplace) const
	{
		do_consume_prop(key, std::move(val), append);
	}

	void set_prop(const char *key, Frame &&val, ::VSMapAppendMode append = ::maReplace) const
	{
		do_consume_prop(key, std::move(val), append);
	}

	void set_prop(const char *key, FilterNode &&val, ::VSMapAppendMode append = ::maReplace) const
	{
		do_consume_prop(key, std::move(val), append);
	}

	void set_prop(const char *key, FilterFunction &&val, ::VSMapAppendMode append = ::maReplace) const
	{
		do_consume_prop(key, std::move(val), append);
	}
};


// Owner of a VSMap.
class MapInstance : public Map {
public:
	static MapInstance create() { return MapInstance{ get_vsapi()->createMap() }; }

	MapInstance(nullptr_t = nullptr) noexcept : MapInstance(static_cast<::VSMap *>(nullptr)) {}
	explicit MapInstance(::VSMap *map) noexcept : Map(map) {}

	MapInstance(const ConstMap &other) noexcept : MapInstance(create()) { copy_from(other); }
	MapInstance(const MapInstance &other) noexcept : MapInstance(static_cast<const ConstMap &>(other)) {}

	MapInstance(MapInstance &&other) noexcept : Map(nullptr) { swap(other); }

	~MapInstance() { get_vsapi()->freeMap(get()); }

	MapInstance &operator=(const ConstMap &other) noexcept { copy_from(other); return *this; }
	MapInstance &operator=(const MapInstance &other) noexcept { return operator=(static_cast<const ConstMap &>(other)); }
	MapInstance &operator=(MapInstance &&other) noexcept { swap(other); return *this; }

	::VSMap *release() noexcept
	{
		::VSMap *map = get();
		set(nullptr);
		return map;
	}

	void swap(MapInstance &other) noexcept
	{
		::VSMap *self = get();
		set(other.get());
		other.set(self);
	}
};


// Reference to a const VSMap.
class ConstMapRef : public ConstMap {
public:
	ConstMapRef(nullptr_t = nullptr) noexcept : ConstMapRef(static_cast<const ::VSMap *>(nullptr)) {}
	explicit ConstMapRef(const ::VSMap *map) noexcept : ConstMap(map) {}

	ConstMapRef(const ConstMap &other) noexcept : ConstMapRef(other.get()) {}

	~ConstMapRef() = default;

	ConstMapRef &operator=(const ConstMap &other) noexcept { set(other.get()); return *this; }
};


// Reference to a VSMap.
class MapRef : public Map {
public:
	MapRef(nullptr_t = nullptr) noexcept : MapRef(static_cast<::VSMap *>(nullptr)) {}
	explicit MapRef(::VSMap *map) noexcept : Map(map) {}

	MapRef(const Map &other) noexcept : MapRef(other.get()) {}

	~MapRef() = default;

	MapRef &operator=(const Map &other) noexcept { set(other.get()); return *this; }
};


// VSFrame reader methods.
class ConstFrameRef {
	const ::VSFrame *m_frame;
protected:
	explicit ConstFrameRef(const ::VSFrame *frame) noexcept : m_frame{ frame } {}
	ConstFrameRef(const ConstFrameRef &other) = default;

	~ConstFrameRef() = default;

	ConstFrameRef &operator=(const ConstFrameRef &other) = default;

	void set(const ::VSFrame *frame) noexcept { m_frame = frame; }
public:
	explicit operator bool() const noexcept { return !!get(); }
	const ::VSFrame *get() const noexcept { return m_frame; }

	// VSAPI::getFrameType
	::VSMediaType type() const noexcept { return static_cast<::VSMediaType>(get_vsapi()->getFrameType(get())); }

	// VSAPI::getFramePropertiesRO
	ConstMapRef frame_props_ro() const noexcept { return ConstMapRef{ get_vsapi()->getFramePropertiesRO(get()) }; }

	// VSAPI::getStride
	ptrdiff_t stride(int plane = 0) const noexcept { return get_vsapi()->getStride(get(), plane); }

	// VSAPI::getReadPtr
	const uint8_t *read_ptr(int plane = 0) const noexcept { return get_vsapi()->getReadPtr(get(), plane); }

	// VSAPI::getVideoFrameFormat
	const ::VSVideoFormat &video_format() const noexcept { return *get_vsapi()->getVideoFrameFormat(get()); }

	// VSAPI::getAudioFrameFormat
	const ::VSAudioFormat &audio_format() const noexcept { return *get_vsapi()->getAudioFrameFormat(get()); }

	// VSAPI::getFrameWidth
	unsigned width(int plane = 0) const noexcept { int ret = get_vsapi()->getFrameWidth(get(), plane); assert(ret >= 0); return ret; }

	// VSAPI::getFrameHeight
	unsigned height(int plane = 0) const noexcept { int ret = get_vsapi()->getFrameHeight(get(), plane); assert(ret >= 0); return ret; }

	// VSAPI::getFrameLength
	unsigned sample_length() const noexcept { int ret = get_vsapi()->getFrameLength(get()); assert(ret >= 0); return ret; }
};

// VSFrame writer methods.
class FrameRef : public ConstFrameRef {
protected:
	explicit FrameRef(::VSFrame *frame) noexcept : ConstFrameRef(frame) {}
	FrameRef(const FrameRef &other) = default;

	~FrameRef() = default;

	FrameRef &operator=(const FrameRef &other) = default;
public:
	::VSFrame *get() const noexcept { return const_cast<::VSFrame *>(ConstFrameRef::get()); }

	// VSAPI::getFramePropertiesRW
	MapRef frame_props_rw() const noexcept { return MapRef{ get_vsapi()->getFramePropertiesRW(get()) }; }

	// VSAPI::getWritePtr
	uint8_t *write_ptr(int plane = 0) const noexcept { return get_vsapi()->getWritePtr(get(), plane); }
};

// Owner of a VSFrame.
class Frame : public FrameRef {
public:
	Frame(nullptr_t = nullptr) noexcept : Frame(static_cast<::VSFrame *>(nullptr)) {}
	explicit Frame(::VSFrame *frame) noexcept : FrameRef(frame) {}

	Frame(Frame &&other) noexcept : Frame() { swap(other); }

	~Frame() { get_vsapi()->freeFrame(get()); }

	Frame &operator=(Frame &&other) noexcept { swap(other); return *this; }

	::VSFrame *release() noexcept
	{
		::VSFrame *frame = get();
		set(nullptr);
		return frame;
	}

	void swap(Frame &other) noexcept
	{
		::VSFrame *self = get();
		set(other.get());
		other.set(self);
	}
};

// Owner of a const VSFrame.
class ConstFrame : public ConstFrameRef {
public:
	ConstFrame(nullptr_t = nullptr) noexcept : ConstFrame(static_cast<const ::VSFrame *>(nullptr)) {}
	explicit ConstFrame(const ::VSFrame *frame) noexcept : ConstFrameRef(frame) {}

	ConstFrame(const ConstFrameRef &other) noexcept : ConstFrame(get_vsapi()->addFrameRef(other.get())) {}
	ConstFrame(const ConstFrame &other) noexcept : ConstFrame(static_cast<const ConstFrameRef &>(other)) {}

	ConstFrame(Frame &&other) noexcept : ConstFrame(other.release()) {}
	ConstFrame(ConstFrame &&other) noexcept : ConstFrame() { swap(other); }

	~ConstFrame() { get_vsapi()->freeFrame(get()); }

	ConstFrame &operator=(const ConstFrameRef &other) noexcept
	{
		ConstFrame temp{ other };
		swap(temp);
		return *this;
	}

	ConstFrame &operator=(const ConstFrame &other) noexcept { return operator=(static_cast<const ConstFrameRef &>(other)); }

	ConstFrame &operator=(Frame &&other) noexcept { set(other.release()); return *this; }
	ConstFrame &operator=(ConstFrame &&other) noexcept { swap(other); return *this; }

	const ::VSFrame *release() noexcept
	{
		const ::VSFrame *frame = get();
		set(nullptr);
		return frame;
	}

	void swap(ConstFrame &other) noexcept
	{
		const ::VSFrame *self = get();
		set(other.get());
		other.set(self);
	}
};

template <>
inline ConstFrame map::detail::get_prop(const ::VSMap *map, const char *key, int index, int *error)
{
	return ConstFrame{ get_vsapi()->mapGetFrame(map, key, index, error) };
}

inline int map::detail::set_prop(::VSMap *map, const char *key, const ConstFrameRef &val, ::VSMapAppendMode append)
{
	return get_vsapi()->mapSetFrame(map, key, val.get(), append);
}

inline int map::detail::consume_prop(::VSMap *map, const char *key, const ConstFrameRef &val, ::VSMapAppendMode append)
{
	return get_vsapi()->mapConsumeFrame(map, key, val.get(), append);
}


// When VSAPI::getFrame fails.
struct GetFrameError : public std::runtime_error {
	using std::runtime_error::runtime_error;
};


// Owner of a VSNode.
class FilterNode {
public:
	typedef std::function<void(ConstFrame, int, const FilterNode &, const char *)> async_callback_type;
private:
	::VSNode *m_node;

	static void VS_CC frame_done_callback(void *user_data, const ::VSFrame *f, int n, ::VSNode *node, const char *error_message)
	{
		async_callback_type *callback = static_cast<async_callback_type *>(user_data);

		try {
			// Node refcount was increased in get_frame_async, so decrement it with RAII.
			(*callback)(ConstFrame{ f }, n, FilterNode{ node }, error_message);
		} catch (...) {
			// ...
		}
		delete callback;
	}
public:
	FilterNode(nullptr_t = nullptr) noexcept : FilterNode(static_cast<::VSNode *>(nullptr)) {}
	explicit FilterNode(::VSNode *node) noexcept : m_node{ node } {}

	FilterNode(const FilterNode &other) noexcept : FilterNode(get_vsapi()->addNodeRef(other.get())) {}
	FilterNode(FilterNode &&other) noexcept : FilterNode() { swap(other); }

	~FilterNode() { get_vsapi()->freeNode(m_node); }

	FilterNode &operator=(FilterNode other) noexcept { swap(other); return *this; }

	::VSNode *get() const noexcept { return m_node; }
	explicit operator bool() const noexcept { return !!get(); }

	// VSAPI::setLinearFilter
	int set_linear() const noexcept { return get_vsapi()->setLinearFilter(get()); }

	// VSAPI::setCacheMode
	void set_cache_mode(::VSCacheMode mode) const noexcept { return get_vsapi()->setCacheMode(get(), static_cast<int>(mode)); }

	// VSAPI::setCacheOptions
	void set_cache_options(int fixed_size, int max_size, int max_history_size) const noexcept
	{
		get_vsapi()->setCacheOptions(get(), fixed_size, max_size, max_history_size);
	}

	// VSAPI::getNodeType
	::VSMediaType type() const noexcept { return static_cast<::VSMediaType>(get_vsapi()->getNodeType(get())); }

	// VSAPI::getVideoInfo
	const ::VSVideoInfo &video_info() const noexcept { return *get_vsapi()->getVideoInfo(get()); }

	// VSAPI::getAudioInfo
	const ::VSAudioInfo &audio_info() const noexcept { return *get_vsapi()->getAudioInfo(get()); }

	// VSAPI::getFrame
	ConstFrame get_frame(int n) const
	{
		char err_msg[256];
		ConstFrame frame = get_frame(std::nothrow, n, err_msg, sizeof(err_msg));
		if (!frame)
			throw GetFrameError(err_msg);
		return frame;
	}

	ConstFrame get_frame(std::nothrow_t, int n, char *err_msg = nullptr, size_t buf_size = 0) const noexcept
	{
		buf_size = buf_size > INT_MAX ? INT_MAX : buf_size;
		return ConstFrame{ get_vsapi()->getFrame(n, get(), err_msg, static_cast<int>(buf_size)) };
	}

	// VSAPI::getFrameAsync
	void get_frame_async(int n, const async_callback_type &callback) const noexcept
	{
		// Add reference to prevent crashes if node is destroyed before callback completes.
		get_vsapi()->addNodeRef(get());
		get_vsapi()->getFrameAsync(n, get(), frame_done_callback, new async_callback_type{ callback });
	}

	::VSNode *release() noexcept
	{
		::VSNode *self = get();
		m_node = nullptr;
		return self;
	}

	void swap(FilterNode &other) noexcept { std::swap(m_node, other.m_node); }
};

template <>
inline FilterNode map::detail::get_prop(const ::VSMap *map, const char *key, int index, int *error)
{
	return FilterNode{ get_vsapi()->mapGetNode(map, key, index, error) };
}

inline int map::detail::set_prop(::VSMap *map, const char *key, const FilterNode &val, ::VSMapAppendMode append)
{
	return get_vsapi()->mapSetNode(map, key, val.get(), append);
}

inline int map::detail::consume_prop(::VSMap *map, const char *key, const FilterNode &val, ::VSMapAppendMode append)
{
	return get_vsapi()->mapConsumeNode(map, key, val.get(), append);
}


// When VSAPI::callFunction fails.
struct FunctionCallError : public std::runtime_error {
	using std::runtime_error::runtime_error;
};

// Owner of a VSFunction.
class FilterFunction {
	::VSFunction *m_function;
public:
	FilterFunction(nullptr_t = nullptr) noexcept : FilterFunction(static_cast<::VSFunction *>(nullptr)) {}
	explicit FilterFunction(::VSFunction *function) noexcept : m_function{ function } {}

	FilterFunction(const FilterFunction &other) noexcept : FilterFunction(get_vsapi()->addFunctionRef(other.get())) {}
	FilterFunction(FilterFunction &&other) noexcept : FilterFunction() { swap(other); }

	~FilterFunction() { get_vsapi()->freeFunction(get()); }

	FilterFunction &operator=(FilterFunction other) noexcept { swap(other); return *this; }

	::VSFunction *get() const noexcept { return m_function; }
	explicit operator bool() const noexcept { return !!get(); }

	MapInstance operator()(const ConstMapRef &in) const
	{
		return call(in);
	}

	// VSAPI::callFunction
	MapInstance call(const ConstMapRef &in) const
	{
		MapInstance out = MapInstance::create();
		call(in, out);
		return out;
	}

	void call(const ConstMapRef &in, const MapRef &out) const
	{
		assert(!out.get_error());
		get_vsapi()->callFunction(get(), in.get(), out.get());
		const char *error = out.get_error();
		if (error)
			throw FunctionCallError{ error };
	}

	::VSFunction *release() noexcept
	{
		::VSFunction *self = get();
		m_function = nullptr;
		return self;
	}

	void swap(FilterFunction &other) noexcept { std::swap(m_function, other.m_function); }
};

template <>
inline FilterFunction map::detail::get_prop(const ::VSMap *map, const char *key, int index, int *error)
{
	return FilterFunction{ get_vsapi()->mapGetFunction(map, key, index, error) };
}

inline int map::detail::set_prop(::VSMap *map, const char *key, const FilterFunction &val, ::VSMapAppendMode append)
{
	return get_vsapi()->mapSetFunction(map, key, val.get(), append);
}

inline int map::detail::consume_prop(::VSMap *map, const char *key, const FilterFunction &val, ::VSMapAppendMode append)
{
	return get_vsapi()->mapConsumeFunction(map, key, val.get(), append);
}


// Wrapper for VSFrameContext.
class FrameContext {
	::VSFrameContext *m_context;
public:
	FrameContext(::VSFrameContext *context = nullptr) noexcept : m_context{ context } {}

	::VSFrameContext *get() const noexcept { return m_context; }
	explicit operator bool() const noexcept { return !!get(); }

	// VSAPI::getFrameFilter
	ConstFrame get_frame(int n, const FilterNode &node) const noexcept
	{
		return ConstFrame{ get_vsapi()->getFrameFilter(n, node.get(), get()) };
	}

	// VSAPI::requestFrameFilter
	void request_frame(int n, const FilterNode &node) const noexcept
	{
		get_vsapi()->requestFrameFilter(n, node.get(), get());
	}

	// VSAPI::releaseFrameEarly
	void release_frame_early(const FilterNode &node, int n) const noexcept
	{
		get_vsapi()->releaseFrameEarly(node.get(), n, get());
	}

	// VSAPI::cacheFrame
	void cache_frame(const ConstFrameRef &frame, int n) const noexcept
	{
		get_vsapi()->cacheFrame(frame.get(), n, get());
	}

	// VSAPI::setFilterError
	void set_error(const char *error_message) const noexcept
	{
		get_vsapi()->setFilterError(error_message, get());
	}

	void set_error(const std::string &error_message) const noexcept
	{
		get_vsapi()->setFilterError(error_message.c_str(), get());
	}
};


// Wrapper for VSPluginFunction.
class PluginFunction {
	::VSPluginFunction *m_function;
public:
	PluginFunction(::VSPluginFunction *function = nullptr) noexcept : m_function{ function } {}

	::VSPluginFunction *get() const noexcept { return m_function; }
	explicit operator bool() const noexcept { return !!get(); }

	// VSAPI::getPluginFunctionName
	const char *name() const noexcept { return get_vsapi()->getPluginFunctionName(get()); }

	// VSAPI::getPluginFunctionArguments
	const char *args() const noexcept { return get_vsapi()->getPluginFunctionArguments(get()); }

	// VSAPI::getPluginFunctionReturnType
	const char *return_type() const noexcept { return get_vsapi()->getPluginFunctionReturnType(get()); }
};

// Wrapper for VSPlugin.
class Plugin {
	::VSPlugin *m_plugin;
public:
	Plugin(::VSPlugin *plugin = nullptr) noexcept : m_plugin{ plugin } {}

	::VSPlugin *get() const noexcept { return m_plugin; }
	explicit operator bool() const noexcept { return !!get(); }

	// VSAPI::getPluginName
	const char *name() const noexcept { return get_vsapi()->getPluginName(get()); }

	// VSAPI::getPluginID
	const char *id() const noexcept { return get_vsapi()->getPluginID(get()); }

	// VSAPI::getPluginNamespace
	const char *namespace_() const noexcept { return get_vsapi()->getPluginNamespace(get()); }

	// VSAPI::getPluginPath
	const char *path() const noexcept { return get_vsapi()->getPluginPath(get()); }

	// VSAPI::getPluginVersion
	int version() const noexcept { return get_vsapi()->getPluginVersion(get()); }

	// VSAPI::getNextPluginFunction
	PluginFunction get_first_function() const noexcept
	{
		return{ get_vsapi()->getNextPluginFunction(nullptr, get()) };
	}

	PluginFunction get_next_function(const PluginFunction &prev) const noexcept
	{
		return{ get_vsapi()->getNextPluginFunction(prev.get(), get()) };
	}

	// VSAPI::invoke
	MapInstance invoke(const char *name, const ConstMap &args) const
	{
		MapInstance out{ get_vsapi()->invoke(get(), name, args.get()) };
		const char *error = out.get_error();
		if (error)
			throw FunctionCallError{ error };
		return out;
	}
};


class Core {
public:
	typedef std::function<void(const ConstMap &, const Map &, const Core &)> public_function;
private:
	::VSCore *m_core;

	static void VS_CC public_function_callback(const ::VSMap *in, ::VSMap *out, void *user, ::VSCore *core, const VSAPI *) noexcept;

	static void VS_CC public_function_free(void *user) noexcept { delete static_cast<public_function *>(user); }
protected:
	explicit Core(::VSCore *core) noexcept : m_core{ core } {}

	Core(const Core &core) = default;

	~Core() = default;

	Core &operator=(const Core &other) = default;

	void set(::VSCore *core) { m_core = core; }
public:
	::VSCore *get() const noexcept { return m_core; }
	explicit operator bool() const noexcept { return !!get(); }

	// VSAPI::createVideoFilter
	void create_video_filter(const Map &out, const char *name, const ::VSVideoInfo &vi, ::VSFilterGetFrame get_frame, ::VSFilterFree free_filter, ::VSFilterMode mode, const ::VSFilterDependency *deps, int num_deps, void *user) const
	{
		get_vsapi()->createVideoFilter(out.get(), name, &vi, get_frame, free_filter, mode, deps, num_deps, user, get());
		const char *error = out.get_error();
		if (error)
			throw FunctionCallError{ error };
	}

	// VSAPI::createVideoFilter2
	FilterNode create_video_filter(const char *name, const ::VSVideoInfo &vi, ::VSFilterGetFrame get_frame, ::VSFilterFree free_filter, ::VSFilterMode mode, const ::VSFilterDependency *deps, int num_deps, void *user) const
	{
		FilterNode node{ get_vsapi()->createVideoFilter2(name, &vi, get_frame, free_filter, mode, deps, num_deps, user, get()) };
		if (!node)
			throw FunctionCallError{ name };
		return node;
	}

	// VSAPI::createAudioFilter
	void create_audio_filter(const Map &out, const char *name, const ::VSAudioInfo &ai, ::VSFilterGetFrame get_frame, ::VSFilterFree free_filter, ::VSFilterMode mode, const ::VSFilterDependency *deps, int num_deps, void *user) const
	{
		get_vsapi()->createAudioFilter(out.get(), name, &ai, get_frame, free_filter, mode, deps, num_deps, user, get());
		const char *error = out.get_error();
		if (error)
			throw FunctionCallError{ error };
	}

	// VSAPI::createAudioFilter2
	FilterNode create_audio_filter(const char *name, const ::VSAudioInfo &ai, ::VSFilterGetFrame get_frame, ::VSFilterFree free_filter, ::VSFilterMode mode, const ::VSFilterDependency *deps, int num_deps, void *user) const
	{
		FilterNode node{ get_vsapi()->createAudioFilter2(name, &ai, get_frame, free_filter, mode, deps, num_deps, user, get()) };
		if (!node)
			throw FunctionCallError{ name };
		return node;
	}

	// VSAPI::newVideoFrame
	Frame new_video_frame(const ::VSVideoFormat &format, unsigned width, unsigned height, const ConstFrameRef &prop_src = ConstFrame{}) const noexcept
	{
		assert(width <= INT_MAX);
		assert(height <= INT_MAX);
		return Frame{ get_vsapi()->newVideoFrame(&format, width, height, prop_src.get(), get()) };
	}

	// VSAPI::newVideoFrame2
	Frame new_video_frame(const ::VSVideoFormat &format, unsigned width, unsigned height, const ConstFrameRef plane_src[3], const int planes[3], const ConstFrameRef &prop_src = ConstFrame{}) const noexcept
	{
		assert(width <= INT_MAX);
		assert(height <= INT_MAX);

		const ::VSFrame *plane_src_[3] = {};
		assert(format.numPlanes <= 3);

		for (int p = 0; p < format.numPlanes; ++p) {
			plane_src_[p] = plane_src[p].get();
		}

		return Frame{ get_vsapi()->newVideoFrame2(&format, width, height, plane_src_, planes, prop_src.get(), get()) };
	}

	// VSAPI::newAudioFrame
	Frame new_audio_frame(const ::VSAudioFormat &format, unsigned num_samples, const ConstFrameRef &prop_src) const noexcept
	{
		assert(num_samples <= INT_MAX);
		return Frame{ get_vsapi()->newAudioFrame(&format, num_samples, prop_src.get(), get()) };
	}

	// VSAPI::newAudioFrame2
	Frame new_audio_frame(const ::VSAudioFormat &format, unsigned num_samples, const ConstFrameRef channel_src[], const int channels[], const ConstFrameRef &prop_src) const noexcept
	{
		assert(num_samples <= INT_MAX);

		const ::VSFrame *channel_src_[64] = {};
		assert(format.numChannels <= 64);

		for (int ch = 0; ch < format.numChannels; ++ch) {
			channel_src_[ch] = channel_src[ch].get();
		}

		return Frame{ get_vsapi()->newAudioFrame2(&format, num_samples, channel_src_, channels, prop_src.get(), get()) };
	}

	// VSAPI::copyFrame
	Frame copy_frame(const ConstFrameRef &f) const noexcept { return Frame{ get_vsapi()->copyFrame(f.get(), get()) }; }

	// VSAPI::queryVideoFormat
	::VSVideoFormat query_video_format(::VSColorFamily color_family, ::VSSampleType sample_type, int bits_per_sample, int subsampling_w, int subsampling_h) const noexcept
	{
		VSVideoFormat format = {};
		int valid = get_vsapi()->queryVideoFormat(&format, color_family, sample_type, bits_per_sample, subsampling_w, subsampling_h, get());
		return valid ? format : ::VSVideoFormat{};
	}

	// VSAPI::queryAudioFormat
	::VSAudioFormat query_audio_format(::VSSampleType sample_type, int bits_per_sample, uint64_t channel_layout) const noexcept
	{
		::VSAudioFormat format = {};
		int valid = get_vsapi()->queryAudioFormat(&format, sample_type, bits_per_sample, channel_layout, get());
		return valid ? format : ::VSAudioFormat{};
	}

	// VSAPI::queryVideoFormatId
	uint32_t query_video_format_id(::VSColorFamily color_family, ::VSSampleType sample_type, int bits_per_sample, int subsampling_w, int subsampling_h) const noexcept
	{
		return get_vsapi()->queryVideoFormatID(color_family, sample_type, bits_per_sample, subsampling_w, subsampling_h, get());
	}

	// VSAPI::getVideoFormatByID
	::VSVideoFormat get_video_format_by_id(uint32_t id) const noexcept
	{
		::VSVideoFormat format = {};
		int valid = get_vsapi()->getVideoFormatByID(&format, id, get());
		return valid ? format : ::VSVideoFormat{};
	}

	// VSAPI::createFunction
	FilterFunction create_function(const public_function &function) const noexcept
	{
		public_function *function_ = new public_function{ function };
		return FilterFunction{ get_vsapi()->createFunction(public_function_callback, function_, public_function_free, get()) };
	}

	// VSAPI::getPluginByID
	Plugin get_plugin_by_id(const char *id) const noexcept { return{ get_vsapi()->getPluginByID(id, get()) }; }

	// VSAPI::getPluginByNamespace
	Plugin get_plugin_by_namespace(const char *ns) const noexcept { return{ get_vsapi()->getPluginByNamespace(ns, get()) }; }

	// VSAPI::getNextPlugin
	Plugin get_first_plugin() const noexcept { return{ get_vsapi()->getNextPlugin(nullptr, get()) }; }
	Plugin get_next_plugin(const Plugin &plugin) const noexcept { return{ get_vsapi()->getNextPlugin(plugin.get(), get()) }; }

	// VSAPI::setMaxCacheSize
	int64_t set_max_cache_size(int64_t bytes) const noexcept { return get_vsapi()->setMaxCacheSize(bytes, get()); }

	// VSAPI::setThreadCount
	unsigned set_thread_count(unsigned threads) const noexcept
	{
		assert(threads <= INT_MAX);
		int result = get_vsapi()->setThreadCount(threads, get());
		assert(result >= 0);
		return result;
	}

	// VSAPI::getCoreInfo
	::VSCoreInfo core_info() const noexcept
	{
		::VSCoreInfo info{};
		get_vsapi()->getCoreInfo(get(), &info);
		return info;
	}
};

class CoreRef : public Core {
public:
	CoreRef(nullptr_t = nullptr) noexcept : CoreRef(static_cast<::VSCore *>(nullptr)) {}
	explicit CoreRef(::VSCore *core) noexcept : Core(core) {}

	CoreRef(const Core &core) noexcept : CoreRef(core.get()) {}

	CoreRef &operator=(const Core &core) noexcept { set(core.get()); return *this; }
};

class CoreInstance : public Core {
public:
	static CoreInstance create(::VSCoreCreationFlags flags = {}) { return CoreInstance{ get_vsapi()->createCore(flags) }; }

	CoreInstance(nullptr_t = nullptr) noexcept : CoreInstance(static_cast<::VSCore *>(nullptr)) {}
	explicit CoreInstance(::VSCore *core) noexcept : Core(core) {}

	CoreInstance(CoreInstance &&other) noexcept : CoreInstance() { swap(other); }

	CoreInstance &operator=(CoreInstance &&other) noexcept { swap(other); return *this; }

	::VSCore *release() noexcept
	{
		::VSCore *self = get();
		set(nullptr);
		return self;
	}

	void swap(CoreInstance &other) noexcept
	{
		::VSCore *self = get();
		set(other.get());
		other.set(self);
	}
};

inline void VS_CC Core::public_function_callback(const ::VSMap *in, ::VSMap *out, void *user, ::VSCore *core, const VSAPI *) noexcept
{
	public_function *func = static_cast<public_function *>(user);

	try {
		(*func)(ConstMapRef{ in }, MapRef{ out }, CoreRef{ core });
	} catch (const std::exception &e) {
		get_vsapi()->mapSetError(out, e.what());
	} catch (...) {
		get_vsapi()->mapSetError(out, "unknown C++ exception");
	}
}


// Base class for filters.
class FilterBase {
	struct FilterReference {
		FilterBase *filter;
		void *context;

		FilterReference(FilterBase *filter, void *context) : filter{ filter }, context{ context } { filter->increment_count(); }

		FilterReference(const FilterReference &) = delete;

		~FilterReference() { filter->decrement_count(); }

		FilterReference &operator=(const FilterReference &) = delete;
	};
protected:
	class FilterDependencyBuilder {
		std::vector<::VSFilterDependency> m_deps;
	public:
		const ::VSFilterDependency *deps() const { return m_deps.data(); }

		int num_deps() const { return static_cast<int>(m_deps.size()); }

		FilterDependencyBuilder &add_dep(const FilterNode &node, ::VSRequestPattern rp = ::rpGeneral)
		{
			m_deps.push_back(::VSFilterDependency{ node.get(), rp });
			return *this;
		}
	};

	static FilterDependencyBuilder make_deps() { return FilterDependencyBuilder{}; }
	static FilterDependencyBuilder simple_dep(const FilterNode &node, ::VSRequestPattern rp = ::rpGeneral) { return make_deps().add_dep(node, rp); }
private:
	std::atomic_int m_refcount;

	static const ::VSFrame *VS_CC filter_get_frame(int n, int activation_reason, void *instance_data, void **frame_data, ::VSFrameContext *frame_context, ::VSCore *core, const ::VSAPI *) noexcept
	{
		FilterReference *ref = static_cast<FilterReference *>(instance_data);
		return ref->filter->get_frame_internal(n, static_cast<::VSActivationReason>(activation_reason), CoreRef{ core }, FrameContext{ frame_context }, ref->context);
	}

	static void VS_CC filter_free(void *instance_data, ::VSCore *, const ::VSAPI *) noexcept
	{
		FilterReference *ref = static_cast<FilterReference *>(instance_data);
		delete ref;
	}

	const ::VSFrame *get_frame_internal(int n, ::VSActivationReason activation_reason, const Core &core, const FrameContext &frame_context, void *node_context)
	{
		ConstFrame frame;

		try {
			switch (activation_reason) {
			case ::arInitial:
				frame = get_frame_initial(n, core, frame_context, node_context);
				break;
			case ::arAllFramesReady:
				frame = get_frame(n, core, frame_context, node_context);
				break;
			case ::arError:
				get_frame_error(n, core, frame_context, node_context);
				break;
			default:
				break;
			}
		} catch (const std::exception &e) {
			std::string err_msg;

			try {
				err_msg += get_name(node_context);
				err_msg += ": ";
				err_msg += e.what();
			} catch (...) {
				// ...
			}

			frame_context.set_error(err_msg);
		} catch (...) {
			frame_context.set_error("unknown C++ exception");
		}

		return frame.release();
	}

	void increment_count()
	{
		++m_refcount;
	}

	void decrement_count()
	{
		int refcount = m_refcount.fetch_sub(1);
		assert(refcount > 0);
		if (refcount == 1)
			delete this;
	}
protected:
	FilterBase() : m_refcount{} {}

	// Filter creation methods. |node_context| can be used to distinguish multiple clips sharing the same filter instance.
	void create_video_filter(const Map &out, const ::VSVideoInfo &vi, ::VSFilterMode mode, const FilterDependencyBuilder &deps, const Core &core, void *node_context = nullptr)
	{
		std::unique_ptr<FilterReference> ref{ new FilterReference{ this, node_context } };
		core.create_video_filter(out, get_name(node_context), vi, filter_get_frame, filter_free, mode, deps.deps(), deps.num_deps(), ref.get());
		ref.release();
	}

	FilterNode create_video_filter(const ::VSVideoInfo &vi, ::VSFilterMode mode, const FilterDependencyBuilder &deps, const Core &core, void *node_context = nullptr)
	{
		std::unique_ptr<FilterReference> ref{ new FilterReference{ this, node_context } };
		FilterNode node = core.create_video_filter(get_name(node_context), vi, filter_get_frame, filter_free, mode, deps.deps(), deps.num_deps(), ref.get());
		ref.release();
		return node;
	}

	void create_audio_filter(const Map &out, const ::VSAudioInfo &ai, ::VSFilterMode mode, const FilterDependencyBuilder &deps, const Core &core, void *node_context = nullptr)
	{
		std::unique_ptr<FilterReference> ref{ new FilterReference{ this, node_context } };
		core.create_audio_filter(out, get_name(node_context), ai, filter_get_frame, filter_free, mode, deps.deps(), deps.num_deps(), ref.get());
		ref.release();
	}

	FilterNode create_audio_filter(const ::VSAudioInfo &ai, ::VSFilterMode mode, const FilterDependencyBuilder &deps, const Core &core, void *node_context = nullptr)
	{
		std::unique_ptr<FilterReference> ref{ new FilterReference{ this, node_context} };
		FilterNode node = core.create_audio_filter(get_name(node_context), ai, filter_get_frame, filter_free, mode, deps.deps(), deps.num_deps(), ref.get());
		ref.release();
		return node;
	}
public:
	// Entry point compatible with VSPublicFunction.
	template <class Derived>
	static void VS_CC filter_create(const ::VSMap *in, ::VSMap *out, void *user, ::VSCore *core, const ::VSAPI *vsapi) noexcept
	{
		// This is the first point where VSAPI is available to plugins.
		if (!get_vsapi())
			set_vsapi(vsapi);

		Derived *d;
		try {
			d = new Derived(user);
		} catch (const std::exception &e) {
			vsapi->mapSetError(out, e.what());
			return;
		} catch (...) {
			vsapi->mapSetError(out, "unknown C++ exception");
			return;
		}

		d->increment_count();

		try {
			d->init(ConstMapRef{ in }, MapRef{ out }, CoreRef{ core });
		} catch (const std::exception &e) {
			std::string err_msg;

			try {
				err_msg += d->get_name(nullptr);
				err_msg += ": ";
				err_msg += e.what();
			} catch (...) {
				// ...
			}

			vsapi->mapSetError(out, err_msg.c_str());
		} catch (...) {
			vsapi->mapSetError(out, "unknown C++ exception");
		}

		d->decrement_count();
	}

	FilterBase(const FilterBase &) = delete;
	FilterBase &operator=(const FilterBase &) = delete;

	virtual ~FilterBase() = default;

	// Used in error messages and when creating node. Must accept a null context.
	virtual const char *get_name(void *node_context) noexcept = 0;

	// Called upon filter invocation. Unlike v3, the derived class is responsible for creating filter nodes by calling
	// the appropriate base class methods. The derived class must not create nodes by directly calling VSCore methods.
	// Each created node increments the filter reference count. The node destructor decrements the reference count.
	// If no nodes are created, the filter is immediately destroyed upon returning.
	virtual void init(const ConstMap &in, const Map &out, const Core &core) = 0;

	// VSFilterFrame. Throwing an exception is equivalent to setting an error on |context|.
	virtual ConstFrame get_frame_initial(int n, const Core &core, const FrameContext &frame_context, void *node_context) = 0;
	virtual ConstFrame get_frame(int n, const Core &core, const FrameContext &frame_context, void *node_context) = 0;
	virtual void get_frame_error(int n, const Core &core, const FrameContext &frame_context, void *node_context) {}
};

} // namespace VSXX4_NAMESPACE

#endif // VAPOURSYNTH4XX_HPP_
