#pragma once

#include <QString>

// Mayak service: ends known foreign VPN cores on the user's request (button in the app).
// Only Browsec's tunnel core is known: <...>\browsec-desktop\resources\xray\browbox.exe.
// Nothing named by the caller is ever terminated; the list is fixed here.
namespace MayakForeignVpnStop {

// True when a full image path is Browsec's tunnel core.
bool isKnownCore(const QString& imagePath);

// Terminates every running known core and waits briefly for each to exit.
// Returns the number of processes that exited.
int stopKnownCores();

}  // namespace MayakForeignVpnStop
