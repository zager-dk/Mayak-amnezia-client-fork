#pragma once
#include <QDebug>
class Logger {
public:
  explicit Logger(const char*) {}
  QNoDebug debug() const { return QNoDebug(); }
  QNoDebug info() const { return QNoDebug(); }
  QNoDebug warning() const { return QNoDebug(); }
  QNoDebug error() const { return QNoDebug(); }
};
