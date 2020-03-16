#pragma once

#ifndef VAPOURSYNTHXX_HPP_
#define VAPOURSYNTHXX_HPP_

#include <exception>
#include <functional>
#include <limits>
#include <memory>
#include <new>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <utility>
#include <string.h>

#include "VapourSynth.h"
#include "VSHelper.h"

// Define this to avoid name conflicts if using in a library.
#ifndef VSXX_NAMESPACE
#define VSXX_NAMESPACE vsxx
#endif

namespace VSXX_NAMESPACE {

class PropertyMapRef;
class ConstPropertyMapRef;

class VideoFrame;
class ConstVideoFrame;

class FilterNode;
class FilterFunc;

class VapourCore;

const VSAPI *get_vsapi() noexcept;


// Policy classes for VSMap getters.
namespace map {

struct MapGetError : public std::runtime_error {
	using std::runtime_error::runtime_error;
};
struct UnsetError : public MapGetError {
	using MapGetError::MapGetError;
};
struct TypeError : public MapGetError {
	using MapGetError::MapGetError;
};
struct IndexError : public MapGetError {
	using MapGetError::MapGetError;
};
struct AppendError : public MapGetError {
	using MapGetError::MapGetError;
};

template <class T>
class Default {
	T m_value;
public:
	explicit Default(const T &value) noexcept : m_value{ value } {}

	const T &operator()(const T &, const char *, ::VSGetPropErrors) noexcept
	{
		return m_value;
	}
};

struct Ignore {
	template <class T>
	T operator()(const T &, const char *, ::VSGetPropErrors) noexcept
	{
		return T{};
	}
};

class Throw {
	unsigned m_mask;
public:
	explicit Throw(unsigned mask = 0) noexcept : m_mask{ mask } {}

	template <class T>
	const T &operator()(const T &x, const char *key, ::VSGetPropErrors error)
	{
		if (m_mask & error)
			return x;

		switch (error) {
		case peUnset:
			throw UnsetError{ key };
		case peType:
			throw TypeError{ key };
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

} // namespace map


namespace detail {

inline const ::VSAPI *vsapi(bool set = false, const ::VSAPI *ptr = nullptr)
{
	static const ::VSAPI *vsapi = nullptr;

	if (set)
		vsapi = ptr;

	return vsapi;
}

template <class T, class U = T>
struct CheckOverflow;

template <class T>
struct CheckOverflow<T, typename std::enable_if<std::is_unsigned<T>::value, T>::type> {
	static bool check(int64_t i64)
	{
		return i64 >= 0 && i64 < std::numeric_limits<T>::max();
	}
};

template <class T>
struct CheckOverflow<T, typename std::enable_if<std::is_signed<T>::value, T>::type> {
	static bool check(int64_t i64)
	{
		return i64 >= std::numeric_limits<T>::min() && i64 <= std::numeric_limits<T>::max();
	}
};

// Template wrappers for VSAPI::propGetX.
template <class T, class U = T>
struct MapGetProp;

// VSAPI::propGetInt.
template <class T>
struct MapGetProp<T, typename std::enable_if<std::is_integral<T>::value &&
                                             !std::is_same<bool, T>::value, T>::type> {
	static T get(const ::VSMap *map, const char *key, int index, int *error) noexcept
	{
		int tmp = 0;

		int64_t val = get_vsapi()->propGetInt(map, key, index, &tmp);
		if (tmp) {
			*error = tmp;
			return 0;
		}

		if (!CheckOverflow<T>::check(val)) {
			*error = peType;
			return 0;
		}

		*error = 0;
		return static_cast<T>(val);
	}
};

// VSAPI::propGetInt for booleans: treat all non-zero as true.
template <>
struct MapGetProp<bool> {
	static bool get(const ::VSMap *map, const char *key, int index, int *error) noexcept
	{
		return !!get_vsapi()->propGetInt(map, key, index, error);
	}
};

// VSAPI::propGetFloat.
template <class T>
struct MapGetProp<T, typename std::enable_if<std::is_floating_point<T>::value, T>::type> {
	static T get(const ::VSMap *map, const char *key, int index, int *error) noexcept
	{
		// Floating-point overflow is defined to saturate.
		return static_cast<T>(get_vsapi()->propGetFloat(map, key, index, error));
	}
};

// VSAPI::propGetData.
template <>
struct MapGetProp<const char *> {
	static const char *get(const ::VSMap *map, const char *key, int index, int *error) noexcept
	{
		return get_vsapi()->propGetData(map, key, index, error);
	}
};

// VSAPI::propGetData + VSAPI::propGetDataSize.
template <>
struct MapGetProp<std::string> {
	static std::string get(const ::VSMap *map, const char *key, int index, int *error) noexcept
	{
		int tmp = 0;

		const char *data = get_vsapi()->propGetData(map, key, index, &tmp);
		if (tmp) {
			*error = tmp;
			return{};
		}

		size_t data_size = get_vsapi()->propGetDataSize(map, key, index, &tmp);

		*error = 0;
		return{ data, data_size };
	}
};

// VSAPI::propGetNode.
template <>
struct MapGetProp<FilterNode> {
	static FilterNode get(const ::VSMap *map, const char *key, int index, int *error) noexcept;
};

// VSAPI::propGetFrame.
template <>
struct MapGetProp<ConstVideoFrame> {
	static ConstVideoFrame get(const ::VSMap *map, const char *key, int index, int *error) noexcept;
};

// VSAPI::propGetFunc.
template <>
struct MapGetProp<FilterFunc> {
	static FilterFunc get(const ::VSMap *map, const char *key, int index, int *error) noexcept;
};

// Template wrappers for VSAPI::propSetX.
template <class T, class U = T>
struct MapSetProp;

// VSAPI::propSetInt.
template <class T>
struct MapSetProp<T, typename std::enable_if<std::is_integral<T>::value, T>::type> {
	static int set(::VSMap *map, const char *key, T x, ::VSPropAppendMode append) noexcept
	{
		if (append != paTouch && x > std::numeric_limits<int64_t>::max())
			return 1;
		return get_vsapi()->propSetInt(map, key, x, append);
	}
};

// VSAPI::propSetFloat.
template <class T>
struct MapSetProp<T, typename std::enable_if<std::is_floating_point<T>::value, T>::type> {
	static int set(::VSMap *map, const char *key, T x, ::VSPropAppendMode append) noexcept
	{
		return get_vsapi()->propSetFloat(map, key, x, append);
	}
};

// VSAPI::propSetData.
template <class T>
struct MapSetProp<T, typename std::enable_if<std::is_convertible<T, const char *>::value, T>::type> {
	static int set(::VSMap *map, const char *key, const T &x, ::VSPropAppendMode append) noexcept
	{
		return get_vsapi()->propSetData(map, key, x, strlen(x), append);
	}
};

template <>
struct MapSetProp<std::string> {
	static int set(::VSMap *map, const char *key, const std::string &x, ::VSPropAppendMode append) noexcept
	{
		return get_vsapi()->propSetData(map, key, x.c_str(), static_cast<int>(x.size()), append);
	}
};

// VSAPI::propSetNode.
template <>
struct MapSetProp<FilterNode> {
	static int set(::VSMap *map, const char *key, const FilterNode &x, ::VSPropAppendMode append) noexcept;
};

// VSAPI::propSetFrame.
template <>
struct MapSetProp<ConstVideoFrame> {
	static int set(::VSMap *map, const char *key, const ConstVideoFrame &x, ::VSPropAppendMode append) noexcept;
};

template <>
struct MapSetProp<VideoFrame> {
	static int set(::VSMap *map, const char *key, const VideoFrame &x, ::VSPropAppendMode append) noexcept;
};

// VSAPI::propSetFunc.
template <>
struct MapSetProp<FilterFunc> {
	static int set(::VSMap *map, const char *key, const FilterFunc &x, ::VSPropAppendMode append) noexcept;
};

// Interface for VSMap.
template <class Map>
class MapBase {
protected:
	Map *m_map;

	explicit MapBase(Map *map = nullptr) noexcept : m_map{ map } {}

	~MapBase() = default;
public:
	explicit operator bool() const noexcept { return get() != nullptr; }
	Map *get() const noexcept { return m_map; }

	// VSAPI::setError.
	template <class T = Map,
	          typename std::enable_if<!std::is_const<T>::value, int>::type = 0>
	void set_error(const char *error_message) const noexcept
	{
		get_vsapi()->setError(get(), error_message);
	}

	// VSAPI::getError.
	const char *get_error() const noexcept
	{
		return get_vsapi()->getError(get());
	}

	// VSAPI::clearMap.
	template <class T = Map,
	          typename std::enable_if<!std::is_const<T>::value, int>::type = 0>
	void clear() const noexcept
	{
		get_vsapi()->clearMap(m_map);
	}

	// VSAPI::propNumKeys.
	size_t size() const noexcept
	{
		return get_vsapi()->propNumKeys(get());
	}

	// VSAPI::propNumElements.
	bool contains(const char *key) const noexcept
	{
		return get_vsapi()->propNumElements(get(), key) >= 0;
	}

	size_t num_elements(const char *key) const
	{
		int ret = get_vsapi()->propNumElements(get(), key);
		if (ret < 0)
			throw map::UnsetError{ key };
		return ret;
	}

	// VSAPI::propGetKey.
	const char *get_key(size_t index) const noexcept
	{
		return get_vsapi()->propGetKey(get(), static_cast<int>(index));
	}

	// VSAPI::propGetX.
	template <class T, class ErrorPolicy = map::Throw,
	          typename std::enable_if<!std::is_convertible<ErrorPolicy, int>::value>::type * = nullptr>
	T get_prop(const char *key, ErrorPolicy error_policy = ErrorPolicy{}) const
	{
		return get_prop<T>(key, 0, error_policy);
	}

	template <class T, class ErrorPolicy = map::Throw>
	T get_prop(const char *key, int index, ErrorPolicy error_policy = ErrorPolicy{}) const
	{
		int error = 0;

		T ret = MapGetProp<T>::get(get(), key, index, &error);
		if (error)
			return error_policy(ret, key, static_cast<::VSGetPropErrors>(error));

		return ret;
	}

	// VSAPI::propDeleteKey.
	template <class T = Map,
	          typename std::enable_if<!std::is_const<T>::value, int>::type = 0>
	void erase(const char *key) const noexcept
	{
		get_vsapi()->propDeleteKey(get(), key);
	}

	// VSAPI::propSetX.
	template <class T, class U = Map,
	          typename std::enable_if<!std::is_const<U>::value, int>::type = 0>
	void set_prop(const char *key, const T &value, ::VSPropAppendMode append = paReplace) const
	{
		if (MapSetProp<T>::set(get(), key, value, append))
			throw map::AppendError{ key };
	}
};

// Base class for VideoFrame and ConstVideoFrame.
// Calls VSAPI::cloneFrameRef on copy and VSAPI::freeFrame on destruction.
template <class Ref>
class FrameRefBase {
protected:
	Ref *m_frame;

	explicit FrameRefBase(Ref *frame = nullptr) noexcept : m_frame{ frame } {}

	FrameRefBase(const FrameRefBase &other) noexcept : FrameRefBase{}
	{
		m_frame = get_vsapi()->cloneFrameRef(other.get());
	}

	FrameRefBase(FrameRefBase &&other) noexcept : FrameRefBase{}
	{
		swap(other);
	}

	~FrameRefBase()
	{
		if (m_frame)
			get_vsapi()->freeFrame(m_frame);
	}

	void operator=(const FrameRefBase &other) noexcept
	{
		FrameRefBase copy{ other };
		swap(copy);
	}

	void operator=(FrameRefBase &&other) noexcept { swap(other); }

	void swap(FrameRefBase &other) noexcept { std::swap(m_frame, other.m_frame); }
public:
	explicit operator bool() const noexcept { return get() != nullptr; }
	Ref *get() const noexcept { return m_frame; }

	Ref *release() noexcept
	{
		Ref *ret = m_frame;
		m_frame = nullptr;
		return ret;
	}

	// VSAPI::getStride.
	int stride(int plane) const noexcept
	{
		return get_vsapi()->getStride(get(), plane);
	}

	// VSAPI::getReadPtr.
	const uint8_t *read_ptr(int plane) const noexcept
	{
		return get_vsapi()->getReadPtr(get(), plane);
	}

	// VSAPI::getWritePtr.
	template <class T = Ref,
	          typename std::enable_if<!std::is_const<T>::value, int>::type = 0>
	uint8_t *write_ptr(int plane) const noexcept
	{
		return get_vsapi()->getWritePtr(get(), plane);
	}

	// VSAPI::getFrameFormat.
	const ::VSFormat &format() const noexcept
	{
		return *get_vsapi()->getFrameFormat(get());
	}

	// VSAPI::getFrameWidth.
	int width(int plane) const noexcept
	{
		return get_vsapi()->getFrameWidth(get(), plane);
	}

	// VSAPI::getFrameHeight.
	int height(int plane) const noexcept
	{
		return get_vsapi()->getFrameHeight(get(), plane);
	}

	// VSAPI::getFramePropsRO.
	template <class T = Ref,
	          typename std::enable_if<std::is_const<T>::value, int>::type = 0>
	ConstPropertyMapRef frame_props() const noexcept;

	// VSAPI::getFramePropsRW.
	template <class T = Ref,
	          typename std::enable_if<!std::is_const<T>::value, int>::type = 0>
	PropertyMapRef frame_props() const noexcept;

	ConstPropertyMapRef frame_props_ro() const noexcept;
};

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


// When VSAPI::getFrame fails.
struct GetFrameError : public std::runtime_error {
	using std::runtime_error::runtime_error;
};


// To instantiate, create a PropertyMapOwner, PropertyMapRef, or ConstPropertyMapRef.
typedef detail::MapBase<::VSMap> PropertyMap;
typedef detail::MapBase<const ::VSMap> ConstPropertyMap;

// Establishes ownership of VSMap.
class PropertyMapOwner : public PropertyMap {
public:
	// VSAPI::createMap.
	static PropertyMapOwner create() noexcept { return PropertyMapOwner{ get_vsapi()->createMap() }; }

	explicit PropertyMapOwner(::VSMap *map = nullptr) noexcept :
		PropertyMap(map)
	{
	}

	PropertyMapOwner(const PropertyMapOwner &other) = delete;

	PropertyMapOwner(PropertyMapOwner &&other) noexcept :
		PropertyMapOwner{}
	{
		swap(other);
	}

	~PropertyMapOwner() { if (m_map) get_vsapi()->freeMap(m_map); }

	PropertyMapOwner &operator=(PropertyMapOwner other) noexcept { swap(other); return *this; }

	::VSMap *release() noexcept
	{
		::VSMap *ret = m_map;
		m_map = nullptr;
		return ret;
	}

	void reset(::VSMap *map = nullptr) noexcept { operator=(PropertyMapOwner{ map }); }
	void swap(PropertyMapOwner &other) noexcept { std::swap(m_map, other.m_map); }
};

// Wraps a raw pointer to VSMap. Does not own map.
class PropertyMapRef : public PropertyMap {
public:
	explicit PropertyMapRef(::VSMap *map = nullptr) noexcept :
		PropertyMap(map)
	{
	}
};

// Wraps a raw pointer to const VSMap. Does not own map.
class ConstPropertyMapRef : public ConstPropertyMap {
public:
	explicit ConstPropertyMapRef(const ::VSMap *map = nullptr) noexcept :
		ConstPropertyMap(map)
	{
	}

	ConstPropertyMapRef(const PropertyMapRef &map) noexcept :
		ConstPropertyMap(map.get())
	{
	}

	explicit ConstPropertyMapRef(const PropertyMapOwner &owner) noexcept :
		ConstPropertyMap(owner.get())
	{
	}
};

// Forward-declared member functions.
template <class Ref>
template <class T, typename std::enable_if<std::is_const<T>::value, int>::type>
ConstPropertyMapRef detail::FrameRefBase<Ref>::frame_props() const noexcept
{
	return frame_props_ro();
}

template <class Ref>
template <class T, typename std::enable_if<!std::is_const<T>::value, int>::type>
PropertyMapRef detail::FrameRefBase<Ref>::frame_props() const noexcept
{
	return PropertyMapRef{ get_vsapi()->getFramePropsRW(get()) };
}

template <class Ref>
ConstPropertyMapRef detail::FrameRefBase<Ref>::frame_props_ro() const noexcept
{
	return ConstPropertyMapRef{ get_vsapi()->getFramePropsRO(get()) };
}


// Reference counted wrapper for VSFrameRef.
// To create new frames, use Core::new_video_frame.
class VideoFrame : public detail::FrameRefBase<::VSFrameRef> {
public:
	explicit VideoFrame(::VSFrameRef *frame = nullptr) noexcept :
		detail::FrameRefBase<::VSFrameRef>(frame)
	{
	}

	using detail::FrameRefBase<::VSFrameRef>::swap;
};

// Reference counted wrapper for const VSFrameRef.
class ConstVideoFrame : public detail::FrameRefBase<const ::VSFrameRef> {
public:
	explicit ConstVideoFrame(const ::VSFrameRef *frame = nullptr) noexcept :
		detail::FrameRefBase<const ::VSFrameRef>(frame)
	{
	}

	ConstVideoFrame(const VideoFrame &frame) noexcept :
		ConstVideoFrame{ get_vsapi()->cloneFrameRef(frame.get()) }
	{
	}

	ConstVideoFrame(VideoFrame &&frame) noexcept :
		ConstVideoFrame{ frame.release() }
	{
	}

	using detail::FrameRefBase<const ::VSFrameRef>::swap;
};

// Forward-declared member functions.
inline ConstVideoFrame detail::MapGetProp<ConstVideoFrame>::get(const ::VSMap *map, const char *key, int index, int *error) noexcept
{
	int tmp = 0;

	const ::VSFrameRef *frame = get_vsapi()->propGetFrame(map, key, index, &tmp);
	if (tmp) {
		*error = tmp;
		return ConstVideoFrame{};
	}

	*error = 0;
	return ConstVideoFrame{ frame };
}

inline int detail::MapSetProp<ConstVideoFrame>::set(::VSMap *map, const char *key, const ConstVideoFrame &x, ::VSPropAppendMode append) noexcept
{
	return get_vsapi()->propSetFrame(map, key, x.get(), append);
}

inline int detail::MapSetProp<VideoFrame>::set(::VSMap *map, const char *key, const VideoFrame &x, ::VSPropAppendMode append) noexcept
{
	return get_vsapi()->propSetFrame(map, key, x.get(), append);
}

// Reference counted wrapper for VSNodeRef.
// Calls VSAPI::cloneNodeRef on copy and VSAPI::freeNode on destruction.
class FilterNode {
public:
	typedef std::function<void(ConstVideoFrame, int, const FilterNode &, const char *)> async_callback_type;
private:
	::VSNodeRef *m_node;

	static void VS_CC frame_done_callback(void *user_data, const ::VSFrameRef *f, int n, ::VSNodeRef *node, const char *error_message)
	{
		async_callback_type *callback = static_cast<async_callback_type *>(user_data);

		// Node was previously cloned in get_frame_async, so it is safe to wrap it.
		try {
			(*callback)(ConstVideoFrame{ f }, n, FilterNode{ node }, error_message);
		} catch (...) {
			// ...
		}
		delete callback;
	}
public:
	explicit FilterNode(::VSNodeRef *node = nullptr) noexcept : m_node{ node } {}

	FilterNode(const FilterNode &other) noexcept : FilterNode{}
	{
		m_node = get_vsapi()->cloneNodeRef(other.get());
	}

	FilterNode(FilterNode &&other) noexcept : FilterNode{}
	{
		swap(other);
	}

	~FilterNode() { if (m_node) get_vsapi()->freeNode(m_node); }

	FilterNode &operator=(FilterNode other) noexcept { swap(other); return *this; }

	explicit operator bool() const noexcept { return get() != nullptr; }
	::VSNodeRef *get() const noexcept  { return m_node; }

	::VSNodeRef *release() noexcept
	{
		::VSNodeRef *ret = m_node;
		m_node = nullptr;
		return ret;
	}

	void reset(::VSNodeRef *node = nullptr) noexcept { operator=(FilterNode{ node }); }
	void swap(FilterNode &other) noexcept { std::swap(m_node, other.m_node); }

	// VSAPI::getFrame.
	ConstVideoFrame get_frame(int n) const
	{
		char err_msg[128];

		ConstVideoFrame frame = get_frame(std::nothrow, n, err_msg, sizeof(err_msg));
		if (!frame)
			throw GetFrameError{ err_msg };

		return frame;
	}

	// VSAPI::getFrame noexcept.
	ConstVideoFrame get_frame(std::nothrow_t, int n, char *err_msg = nullptr, size_t buf_size = 0) const noexcept
	{
		return ConstVideoFrame{ get_vsapi()->getFrame(n, get(), err_msg, static_cast<int>(buf_size)) };
	}

	// VSAPI::getFrameAsync.
	void get_frame_async(int n, const async_callback_type &callback) const
	{
		// Add reference in case node is destroyed.
		::VSNodeRef *node = get_vsapi()->cloneNodeRef(get());

		get_vsapi()->getFrameAsync(n, node, &FilterNode::frame_done_callback, new async_callback_type{ callback });
	}

	// VSAPI::getFrameFilter.
	ConstVideoFrame get_frame_filter(int n, VSFrameContext *frame_ctx) const noexcept
	{
		return ConstVideoFrame{ get_vsapi()->getFrameFilter(n, get(), frame_ctx) };
	}

	// VSAPI::requestFrameFilter.
	void request_frame_filter(int n, VSFrameContext *frame_ctx) const noexcept
	{
		get_vsapi()->requestFrameFilter(n, get(), frame_ctx);
	}

	// VSAPI::releaseFrameEarly.
	void release_frame_early(int n, VSFrameContext *frame_ctx) const noexcept
	{
		get_vsapi()->releaseFrameEarly(get(), n, frame_ctx);
	}

	// VSAPI::getVideoInfo.
	const ::VSVideoInfo &video_info() const noexcept
	{
		return *get_vsapi()->getVideoInfo(get());
	}
};

// Forward-declared member functions.
inline FilterNode detail::MapGetProp<FilterNode>::get(const ::VSMap *map, const char *key, int index, int *error) noexcept
{
	int tmp = 0;

	::VSNodeRef *node = get_vsapi()->propGetNode(map, key, index, &tmp);
	if (tmp) {
		*error = tmp;
		return FilterNode{};
	}

	*error = 0;
	return FilterNode{ node };
}

inline int detail::MapSetProp<FilterNode>::set(::VSMap *map, const char *key, const FilterNode &x, ::VSPropAppendMode append) noexcept
{
	return get_vsapi()->propSetNode(map, key, x.get(), append);
}


// Reference counted wrapper for VSFuncRef.
// Calls VSAPI::cloneFuncRef on copy and VSAPI::freeFunc on destruction.
class FilterFunc {
public:
	typedef std::function<void(const ConstPropertyMap &, const PropertyMap &, const VapourCore &)> callback_type;
private:
	::VSFuncRef *m_func;

	static void VS_CC filter_func_callback(const ::VSMap *in, ::VSMap *out, void *user_data, ::VSCore *core, const ::VSAPI *vsapi);
public:
	static FilterFunc create(const callback_type &callback, const VapourCore &core);

	explicit FilterFunc(::VSFuncRef *func = nullptr) noexcept : m_func{ func } {}

	FilterFunc(const FilterFunc &other) noexcept : FilterFunc{}
	{
		m_func = get_vsapi()->cloneFuncRef(other.get());
	}

	FilterFunc(FilterFunc &&other) noexcept : FilterFunc{}
	{
		swap(other);
	}

	~FilterFunc()
	{
		if (m_func)
			get_vsapi()->freeFunc(m_func);
	}

	FilterFunc &operator=(FilterFunc other) { swap(other); return *this; }

	explicit operator bool() const noexcept { return get() != nullptr; }
	::VSFuncRef *get() const noexcept { return m_func; }

	::VSFuncRef *release() noexcept
	{
		::VSFuncRef *ret = m_func;
		m_func = nullptr;
		return ret;
	}

	void reset(::VSFuncRef *func = nullptr) noexcept { operator=(FilterFunc{ func }); }
	void swap(FilterFunc &other) noexcept { std::swap(m_func, other.m_func); }

	// VSAPI::callFunc.
	void operator()(const ConstPropertyMap &in, const PropertyMap &out) const noexcept
	{
		get_vsapi()->callFunc(get(), in.get(), out.get(), nullptr, nullptr);
	}
};

// Forward-declared member functions.
inline FilterFunc detail::MapGetProp<FilterFunc>::get(const ::VSMap *map, const char *key, int index, int *error) noexcept
{
	int tmp = 0;

	::VSFuncRef *func = get_vsapi()->propGetFunc(map, key, index, &tmp);
	if (tmp) {
		*error = tmp;
		return FilterFunc{};
	}

	*error = 0;
	return FilterFunc{ func };
}

inline int detail::MapSetProp<FilterFunc>::set(::VSMap *map, const char *key, const FilterFunc &x, ::VSPropAppendMode append) noexcept
{
	return get_vsapi()->propSetFunc(map, key, x.get(), append);
}


// Interface for VSPlugin.
class Plugin {
	::VSPlugin *m_plugin;
public:
	explicit Plugin(::VSPlugin *plugin = nullptr) noexcept : m_plugin{ plugin }
	{
	}

	::VSPlugin *get() const noexcept { return m_plugin; }

	// VSAPI::getFunctions.
	PropertyMapOwner functions() const noexcept
	{
		return PropertyMapOwner{ get_vsapi()->getFunctions(get()) };
	}

	// VSAPI::registerFunction.
	// For filters using vsxx::FilterBase, FilterBase::filter_create acts as |args_func|.
	void register_function(const char *name, const char *args, ::VSPublicFunction args_func, void *function_data) const noexcept
	{
		get_vsapi()->registerFunction(name, args, args_func, function_data, get());
	}

	// VSAPI::invoke.
	PropertyMapOwner invoke(const char *name, const ConstPropertyMap &args) const noexcept
	{
		return PropertyMapOwner{ get_vsapi()->invoke(get(), name, args.get()) };
	}

	// VSAPI::getPluginPath
	const char *path() const noexcept
	{
		return get_vsapi()->getPluginPath(m_plugin);
	}
};


// Interface for VSCore.
// To instantiate, create a VapourCoreRef or VapourCoreOwner.
class VapourCore {
protected:
	::VSCore *m_core;

	explicit VapourCore(::VSCore *core = nullptr) noexcept : m_core{ core } {}

	~VapourCore() = default;
public:
	explicit operator bool() const noexcept { return get() != nullptr; }
	::VSCore *get() const noexcept { return m_core; }

	// VSAPI::getCoreInfo.
	::VSCoreInfo core_info() const noexcept
	{
		::VSCoreInfo info;
		get_vsapi()->getCoreInfo2(get(), &info);
		return info;
	}

	// VSAPI::newVideoFrame.
	VideoFrame new_video_frame(const ::VSFormat &format, int width, int height,
	                           const ConstVideoFrame &prop_src = ConstVideoFrame{}) const noexcept
	{
		return VideoFrame{ get_vsapi()->newVideoFrame(&format, width, height, prop_src.get(), get()) };
	}

	// VSAPI::newVideoFrame2.
	VideoFrame new_video_frame(const ::VSFormat &format, int width, int height,
	                           const ConstVideoFrame plane_src[3], const int planes[3],
	                           const ConstVideoFrame &prop_src = ConstVideoFrame{})
	{
		const ::VSFrameRef *plane_src_[3];
		const ::VSFrameRef **plane_src_ptr = nullptr;

		if (plane_src && planes) {
			for (int i = 0; i < 3; ++i) {
				plane_src_[i] = plane_src[i].get();
			}
			plane_src_ptr = &plane_src_[0];
		}

		return VideoFrame{ get_vsapi()->newVideoFrame2(&format, width, height, plane_src_ptr, planes, prop_src.get(), get()) };
	}

	// VSAPI::copyFrame.
	VideoFrame copy_frame(const ConstVideoFrame &f) const noexcept
	{
		return VideoFrame{ get_vsapi()->copyFrame(f.get(), get()) };
	}

	// VSAPI::copyFrameProps.
	void copy_frame_props(const ConstVideoFrame &src, const VideoFrame &dst) const noexcept
	{
		get_vsapi()->copyFrameProps(src.get(), dst.get(), get());
	}

	// VSAPI::getPluginById.
	Plugin get_plugin_by_id(const char *identifier) const noexcept
	{
		return Plugin{ get_vsapi()->getPluginById(identifier, get()) };
	}

	// VSAPI::getPluginByNs.
	Plugin get_plugin_by_ns(const char *ns) const noexcept
	{
		return Plugin{ get_vsapi()->getPluginByNs(ns, get()) };
	}

	// VSAPI::getPlugins.
	const PropertyMapOwner plugins() const noexcept
	{
		return PropertyMapOwner{ get_vsapi()->getPlugins(get()) };
	}

	// VSAPI::getFormatPreset.
	const ::VSFormat *format_preset(::VSPresetFormat id) const noexcept
	{
		return get_vsapi()->getFormatPreset(id, get());
	}

	// VSAPI::registerFormat.
	const ::VSFormat *register_format(::VSColorFamily color_family, ::VSSampleType sample_type,
	                                  int bits_per_sample, int subsampling_w, int subsampling_h) const noexcept
	{
		return get_vsapi()->registerFormat(color_family, sample_type, bits_per_sample, subsampling_w, subsampling_h, get());
	}

	// VSAPI::setMaxCacheSize.
	int64_t set_max_cache_size(int64_t bytes) const noexcept
	{
		return get_vsapi()->setMaxCacheSize(bytes, get());
	}

	// VSAPI::setThreadCount.
	int set_thread_count(int threads) const noexcept
	{
		return get_vsapi()->setThreadCount(threads, get());
	}
};

// Establishes ownership of VSCore.
class VapourCoreOwner : public VapourCore {
public:
	static VapourCoreOwner create(int threads = 0) noexcept
	{
		return VapourCoreOwner{ get_vsapi()->createCore(threads) };
	}

	explicit VapourCoreOwner(::VSCore *core = nullptr) noexcept : VapourCore(core) {}
	VapourCoreOwner(const VapourCoreOwner &) = delete;
	VapourCoreOwner(VapourCoreOwner &&other) noexcept : VapourCore() { swap(other); }

	~VapourCoreOwner() { if (m_core) get_vsapi()->freeCore(m_core); }

	VapourCoreOwner &operator=(VapourCoreOwner other) noexcept { swap(other); return *this; }

	::VSCore *release() noexcept
	{
		::VSCore *ret = m_core;
		m_core = nullptr;
		return ret;
	}

	void reset(::VSCore *core = nullptr) noexcept { operator=(VapourCoreOwner{ core }); }
	void swap(VapourCoreOwner &other) noexcept { std::swap(m_core, other.m_core); }
};

// Wraps a raw pointer to VSCore. Does not own pointer.
class VapourCoreRef : public VapourCore {
public:
	explicit VapourCoreRef(::VSCore *core = nullptr) noexcept : VapourCore(core) {}
	explicit VapourCoreRef(const VapourCoreOwner &owner) noexcept : VapourCore(owner.get()) {}
};

// Forward-declared member functions
inline void VS_CC FilterFunc::filter_func_callback(const ::VSMap *in, ::VSMap *out, void *user_data, ::VSCore *core, const ::VSAPI *vsapi)
{
	const callback_type &callback = *static_cast<callback_type *>(user_data);

	try {
		callback(ConstPropertyMapRef{ in }, PropertyMapRef{ out }, VapourCoreRef{ core });
	} catch (const std::exception &e) {
		get_vsapi()->setError(out, e.what());
	} catch (...) {
		get_vsapi()->setError(out, "unknown C++ exception");
	}
}

inline FilterFunc FilterFunc::create(const callback_type &callback, const VapourCore &core)
{
	auto delete_callback = [](void *ptr) { delete static_cast<callback_type *>(ptr); };
	return FilterFunc{ get_vsapi()->createFunc(&FilterFunc::filter_func_callback, new callback_type{ callback }, delete_callback, core.get(), get_vsapi()) };
}


// Base class for filters.
class FilterBase {
	static void VS_CC filter_init(::VSMap *in, ::VSMap *out, void **instance_data, ::VSNode *node, ::VSCore *, const ::VSAPI *) noexcept
	{
		FilterBase *filter = static_cast<FilterBase *>(*instance_data);
		filter->set_node_video_info(PropertyMapRef{ in }, PropertyMapRef{ out }, node);
	}

	static const ::VSFrameRef *VS_CC filter_get_frame(int n, int activation_reason, void **instance_data, void **, ::VSFrameContext *frame_ctx, ::VSCore *core, const ::VSAPI *) noexcept
	{
		FilterBase *filter = static_cast<FilterBase *>(*instance_data);
		return filter->get_frame_internal(n, static_cast<::VSActivationReason>(activation_reason), VapourCoreRef{ core }, frame_ctx);
	}

	static void VS_CC filter_free(void *instance_data, ::VSCore *, const ::VSAPI *) noexcept
	{
		FilterBase *filter = static_cast<FilterBase *>(instance_data);
		delete filter;
	}

	void create_filter(const ConstPropertyMap &in, const PropertyMap &out, const VapourCore &core) noexcept
	{
		bool initialized = false;

		try {
			std::pair<VSFilterMode, int> flags = init(in, out, core);

			get_vsapi()->createFilter(in.get(), out.get(), get_name(0),
			                          &FilterBase::filter_init, &FilterBase::filter_get_frame, &FilterBase::filter_free,
			                          flags.first, flags.second, this, core.get());
			initialized = true;
			post_init(in, out, core);
		} catch (const std::exception &e) {
			std::string err_msg;

			try {
				err_msg += get_name(0);
				err_msg += ": ";
				err_msg += e.what();
			} catch (...) {
				// ...
			}

			out.set_error(err_msg.c_str());
		} catch (...) {
			out.set_error("unknown C++ exception");
		}

		// If the filter creation fails, the core will not call VSFilterFree.
		if (!initialized && out.get_error())
			delete this;
	}

	const ::VSFrameRef *get_frame_internal(int n, ::VSActivationReason activation_reason, const VapourCore &core, ::VSFrameContext *frame_ctx)
	{
		ConstVideoFrame frame;

		try {
			switch (activation_reason) {
			case arInitial:
				frame = get_frame_initial(n, core, frame_ctx);
				break;
			case arFrameReady:
				get_frame_one_ready(n, core, frame_ctx);
				break;
			case arAllFramesReady:
				frame = get_frame(n, core, frame_ctx);
				break;
			case arError:
				get_frame_error(n, core, frame_ctx);
				break;
			default:
				break;
			}
		} catch (const std::exception &e) {
			std::string err_msg;

			try {
				err_msg += get_name(get_vsapi()->getOutputIndex(frame_ctx));
				err_msg += ": ";
				err_msg += e.what();
			} catch (...) {
				// ...
			}

			get_vsapi()->setFilterError(err_msg.c_str(), frame_ctx);
		} catch (...) {
			get_vsapi()->setFilterError("unknown C++ exception", frame_ctx);
		}

		return frame.release();
	}

	void set_node_video_info(const PropertyMap &in, const PropertyMap &out, ::VSNode *node) noexcept
	{
		std::pair<const ::VSVideoInfo *, size_t> vi = get_video_info();
		get_vsapi()->setVideoInfo(vi.first, static_cast<int>(vi.second), node);
	}
protected:
	FilterBase() = default;
public:
	template <class Derived>
	static void VS_CC filter_create(const ::VSMap *in, ::VSMap *out, void *user_data, ::VSCore *core, const ::VSAPI *vsapi) noexcept
	{
		// This is the first point where VSAPI is available to plugins.
		if (!get_vsapi())
			set_vsapi(vsapi);

		try {
			FilterBase *filter = new Derived{ user_data };
			filter->create_filter(ConstPropertyMapRef{ in }, PropertyMapRef{ out }, VapourCoreRef{ core });
		} catch (const std::exception &e) {
			vsapi->setError(out, e.what());
		} catch (...) {
			vsapi->setError(out, "unknown C++ exception");
		}
	}

	FilterBase(const FilterBase &) = delete;
	FilterBase &operator=(const FilterBase &) = delete;

	virtual ~FilterBase() = default;

	// Used in error messages and when creating node. Must accept |index| of 0.
	virtual const char *get_name(int index) noexcept = 0;

	// Filter creation function. VSAPI::createFilter is called upon return.
	// Throwing an exception is equivalent to setting an error on |out|.
	virtual std::pair<::VSFilterMode, int> init(const ConstPropertyMap &in, const PropertyMap &out, const VapourCore &core) = 0;

	// Called after VSAPI::createFilter returns. Only for functions that need to manipulate the return map.
	// Throwing an exception is equivalent to setting an error on |out|.
	virtual void post_init(const ConstPropertyMap &in, const PropertyMap &out, const VapourCore &core) {}

	// Used in VSFilterInit.
	virtual std::pair<const ::VSVideoInfo *, size_t> get_video_info() noexcept = 0;

	// VSFilterFrame. Throwing an exception is equivalent to setting a filter error on |frame_ctx|.
	virtual ConstVideoFrame get_frame_initial(int n, const VapourCore &core, ::VSFrameContext *frame_ctx) = 0;
	virtual void get_frame_one_ready(int n, const VapourCore &core, ::VSFrameContext *frame_ctx) {}
	virtual ConstVideoFrame get_frame(int n, const VapourCore &core, ::VSFrameContext *frame_ctx) = 0;
	virtual void get_frame_error(int n, const VapourCore &core, ::VSFrameContext *frame_ctx) {}
};

} // namespace vsxx

#endif // VAPOURSYNTHXX_HPP_
