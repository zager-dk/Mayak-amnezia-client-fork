cmake_minimum_required(VERSION 3.25)
project(MayakInvitePreview LANGUAGES CXX)
find_package(Qt6 REQUIRED COMPONENTS Core Gui Qml Quick QuickControls2 LinguistTools)
qt_standard_project_setup()
qt_add_executable(MayakInvitePreview main.cpp)
qt6_add_resources(PREVIEW_RESOURCES
    ${CMAKE_CURRENT_LIST_DIR}/../../client/images/images.qrc
    ${CMAKE_CURRENT_LIST_DIR}/../../client/ui/qml/qml.qrc
)
target_sources(MayakInvitePreview PRIVATE ${PREVIEW_RESOURCES})
target_link_libraries(MayakInvitePreview PRIVATE Qt6::Core Qt6::Gui Qt6::Qml Qt6::Quick Qt6::QuickControls2)
qt6_add_translations(MayakInvitePreview
    TS_FILES ${CMAKE_CURRENT_LIST_DIR}/../../client/translations/amneziavpn_ru_RU.ts
    SOURCES ${CMAKE_CURRENT_LIST_DIR}/../../client/ui/qml/Pages2/PageUpdate.qml
    RESOURCE_PREFIX "/translations"
)
target_compile_definitions(MayakInvitePreview PRIVATE
    MAYAK_QML_MODULES_DIR="${CMAKE_CURRENT_LIST_DIR}/../../client/ui/qml/Modules"
    MAYAK_PREVIEW_MAIN_QML="${CMAKE_CURRENT_LIST_DIR}/MockMayakInvite.qml"
)
