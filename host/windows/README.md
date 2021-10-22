This Wiki guides you through the process of compiling and running the memory_regions.cpp on Windows host.
if you are not interested in the compilation process, you can download the Memory_Map.zip to your Windows host (should be x64), unzip it and run the Memory_Map.exe inside it to produce the mem_regions.json file you need.

Pre-requests:
1. Visual Studio
4. git for windows
5. json-c x64 installed on Windows:
    * git clone https://github.com/Microsoft/vcpkg.git
    * cd vcpkg
    * bootstrap-vcpkg.bat
    * vcpkg.exe integrate install
    * vcpkg.exe install jsoncpp:x64-windows


Using Visual Studio:

1. Create a new CPP project
2. copy memory_regions.cpp into that project
3. Build solution - Release x64 (Works only on x64 OS for now)
