#pragma once
class KillSwitch {
public:
  static KillSwitch* instance() { static KillSwitch value; return &value; }
  bool disableKillSwitch() { return true; }
};
