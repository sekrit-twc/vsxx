# To compile example.
c++ -std=c++11 -shared -I. -fPIC -fvisibility=hidden example/invert_example.cpp vsxx_pluginmain.cpp -o invert_example.so
c++ -std=c++11 -I. -D__STDC_FORMAT_MACROS example/pipe_example.cpp -lvapoursynth-script -o pipe_example
