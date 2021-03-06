#pragma once

#include "CsIns.hpp"
#include "Disasm.hpp"

using CSparcInsClass =
    CCsIns<sparc_insn_group, sparc_reg, sparc_op_type, sparc_insn>;

class CSparcV9Disasm : public CCsDisasm<CSparcInsClass> {
public:
  CSparcV9Disasm(unsigned int mode = cs_mode::CS_MODE_V9 +
                                     cs_mode::CS_MODE_BIG_ENDIAN)
      : CCsDisasm(cs_arch::CS_ARCH_SPARC, mode) {}
};

class CSparcDisasm : public CCsDisasm<CSparcInsClass> {
public:
  CSparcDisasm(unsigned int mode = cs_mode::CS_MODE_BIG_ENDIAN)
      : CCsDisasm(cs_arch::CS_ARCH_SPARC, mode) {}
};
