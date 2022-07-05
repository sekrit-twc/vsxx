# To compile example.
set -x
c++ -std=c++14 -shared -I. -Ivapoursynth -fPIC -fvisibility=hidden example/invert_example.cpp example/invert4_example.cpp vsxx_pluginmain.cpp vsxx4_pluginmain.cpp -o invert_example.so
c++ -std=c++14 -shared -I. -Ivapoursynth -fPIC -fvisibility=hidden example/psnr_example.cpp vsxx4_pluginmain.cpp -o psnr_example.so
c++ -std=c++14 -I. -Ivapoursynth -D__STDC_FORMAT_MACROS example/pipe_example.cpp -lvapoursynth-script -o pipe_example
c++ -std=c++14 -I. -Ivapoursynth -D__STDC_FORMAT_MACROS example/pipe4_example.cpp -ldl -o pipe4_example
