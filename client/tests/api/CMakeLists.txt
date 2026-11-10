add_executable(test_ui_api_services_model_and_controller
    testUiApiServicesModelAndController.cpp
)

target_link_libraries(test_ui_api_services_model_and_controller PRIVATE
    Qt6::Test
    test_common
)

add_executable(test_ui_news_model_and_controller
    testUiNewsModelAndController.cpp
)

target_link_libraries(test_ui_news_model_and_controller PRIVATE
    Qt6::Test
    test_common
)

add_executable(test_gateway_service_import
    testGatewayServiceImport.cpp
)

target_link_libraries(test_gateway_service_import PRIVATE
    Qt6::Test
    test_common
)

add_executable(test_update_controller
    testUpdateController.cpp
)

add_executable(test_mayak_runtime testMayakRuntime.cpp)
target_link_libraries(test_mayak_runtime PRIVATE Qt6::Test test_common)
add_test(NAME MayakRuntimeTest COMMAND test_mayak_runtime)

add_executable(test_mayak_xray_paths testMayakXrayPaths.cpp)
target_link_libraries(test_mayak_xray_paths PRIVATE Qt6::Test test_common)
add_test(NAME MayakXrayPathsTest COMMAND test_mayak_xray_paths)

add_executable(test_mayak_split_tunneling testMayakSplitTunneling.cpp)
target_link_libraries(test_mayak_split_tunneling PRIVATE Qt6::Test test_common)
add_test(NAME MayakSplitTunnelingTest COMMAND test_mayak_split_tunneling)

add_executable(test_mayak_device_key testMayakDeviceKey.cpp)
target_link_libraries(test_mayak_device_key PRIVATE Qt6::Test test_common)
add_test(NAME MayakDeviceKeyTest COMMAND test_mayak_device_key)

add_executable(test_mayak_foreign_vpn testMayakForeignVpn.cpp)
if(WIN32)
    target_sources(test_mayak_foreign_vpn PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../../platforms/windows/daemon/mayakforeignvpnstop.cpp)
endif()
target_link_libraries(test_mayak_foreign_vpn PRIVATE Qt6::Test test_common)
add_test(NAME MayakForeignVpnTest COMMAND test_mayak_foreign_vpn)

add_executable(test_mayak_permission_preflight testMayakPermissionPreflight.cpp)
target_link_libraries(test_mayak_permission_preflight PRIVATE Qt6::Test test_common)
add_test(NAME MayakPermissionPreflightTest COMMAND test_mayak_permission_preflight)

target_link_libraries(test_update_controller PRIVATE
    Qt6::Test
    test_common
)
target_compile_definitions(test_update_controller PRIVATE MAYAK_SOURCE_DIR="${CMAKE_SOURCE_DIR}")

add_test(NAME UiApiServicesModelAndControllerTest COMMAND test_ui_api_services_model_and_controller)
add_test(NAME UiNewsModelAndControllerTest COMMAND test_ui_news_model_and_controller)
add_test(NAME GatewayServiceImportTest COMMAND test_gateway_service_import)
add_test(NAME UpdateControllerTest COMMAND test_update_controller)

amnezia_copy_runtime_dlls()
