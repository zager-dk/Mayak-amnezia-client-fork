# Additive Mayak visual branding for the Windows Qt Installer Framework package.
# Keep all behavior and identity configuration in CPack.cmake and installer scripts.
if(NOT WIN32)
    message(FATAL_ERROR "Mayak IFW branding is Windows-only")
endif()

set(MAYAK_IFW_BRANDING_DIR "${CMAKE_SOURCE_DIR}/deploy/installer/qif/branding")

# These properties are documented by the project's CMake 3.31.8 CPackIFW module.
set(CPACK_IFW_PACKAGE_LOGO        "${MAYAK_IFW_BRANDING_DIR}/mayak-logo-64.png")
set(CPACK_IFW_PACKAGE_BANNER      "${MAYAK_IFW_BRANDING_DIR}/mayak-banner-600x80.png")
set(CPACK_IFW_PACKAGE_WATERMARK   "${MAYAK_IFW_BRANDING_DIR}/mayak-watermark-164x314.png")
set(CPACK_IFW_PACKAGE_WINDOW_ICON "${MAYAK_IFW_BRANDING_DIR}/mayak-logo-128.png")
set(CPACK_IFW_PACKAGE_ICON        "${MAYAK_IFW_BRANDING_DIR}/mayak.ico")
set(CPACK_IFW_PACKAGE_TITLE_COLOR "#ECEFF6")
set(CPACK_IFW_PACKAGE_STYLE_SHEET "${MAYAK_IFW_BRANDING_DIR}/mayak-ifw.qss")
# Qt IFW hides WatermarkPixmap while the page list is shown. Keep every page
# and transition intact, but clear the left visual rail so the F7 watermark shows.
set(CPACK_IFW_PACKAGE_WIZARD_SHOW_PAGE_LIST OFF)
