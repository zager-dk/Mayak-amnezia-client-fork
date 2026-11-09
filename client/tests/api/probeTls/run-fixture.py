"""Standalone real TLS regression runner. Use a compiler/SDK configured shell.
Only loopback is contacted; ephemeral certificates and process-local trust are used.
Requires Python cryptography, CMake, Ninja and Qt Core/Network/Test.
"""
from pathlib import Path
import argparse, os, subprocess, sys, tempfile
p=argparse.ArgumentParser()
p.add_argument('--qt', required=True, type=Path)
p.add_argument('--cmake', default='cmake')
p.add_argument('--ninja', default='ninja')
p.add_argument('--build-root', required=True, type=Path)
p.add_argument('--report', type=Path)
args=p.parse_args()
here=Path(__file__).resolve().parent
client=here.parents[2]
project=args.build_root.resolve()/'project'; build=args.build_root.resolve()/'build'
project.mkdir(parents=True,exist_ok=True)
cmake=f'''cmake_minimum_required(VERSION 3.21)
project(MayakProbeHttpClose LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_AUTOMOC ON)
find_package(Qt6 6.10.3 REQUIRED COMPONENTS Core Network Test)
add_executable(local_tls_probe_tests "{(here/'localTlsProbeTests.cpp').as_posix()}" "{(client/'core/utils/mayakTunnelProbe.cpp').as_posix()}" "{(client/'core/utils/mayakTunnelProbe.h').as_posix()}")
target_include_directories(local_tls_probe_tests PRIVATE "{(client/'core/utils').as_posix()}")
target_compile_definitions(local_tls_probe_tests PRIVATE MAYAK_TUNNEL_PROBE_TESTING)
target_link_libraries(local_tls_probe_tests PRIVATE Qt6::Core Qt6::Network Qt6::Test)
add_library(probe_production_compile OBJECT "{(client/'core/utils/mayakTunnelProbe.cpp').as_posix()}" "{(client/'core/utils/mayakTunnelProbe.h').as_posix()}")
target_link_libraries(probe_production_compile PRIVATE Qt6::Core Qt6::Network)
if(WIN32)
  target_link_libraries(local_tls_probe_tests PRIVATE ws2_32)
endif()
'''
(project/'CMakeLists.txt').write_text(cmake,encoding='utf-8')
subprocess.run([args.cmake,'-S',str(project),'-B',str(build),'-G','Ninja','-DCMAKE_MAKE_PROGRAM='+args.ninja,'-DCMAKE_PREFIX_PATH='+str(args.qt.resolve()),'-DCMAKE_BUILD_TYPE=Release','-DCMAKE_CXX_FLAGS_DEBUG=/Z7 /Ob0 /Od /RTC1'],check=True)
subprocess.run([args.cmake,'--build',str(build),'--target','local_tls_probe_tests','probe_production_compile','-j','2'],check=True)
with tempfile.TemporaryDirectory(prefix='mayak-local-tls-', dir=args.build_root.resolve()) as certificates:
 subprocess.run([sys.executable,str(here/'generate-fixture.py'),certificates],check=True)
 env=dict(os.environ);env['PATH']=str(args.qt.resolve()/'bin')+os.pathsep+env.get('PATH','');env['MAYAK_LOCAL_TLS_FIXTURE_DIR']=certificates
 executable=build/('local_tls_probe_tests.exe' if os.name=='nt' else 'local_tls_probe_tests')
 command=[str(executable)]
 if args.report: command+=['-o',str(args.report.resolve())+',txt']
 result=subprocess.run(command,env=env)
sys.exit(result.returncode)
