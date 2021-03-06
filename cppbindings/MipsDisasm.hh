#pragma once

#include "CsIns.hpp"
#include "Disasm.hpp"

using CMipsInsClass =
    CCsIns<mips_insn_group, mips_reg, mips_op_type, mips_insn>;

class CMicroMipsCDisasm : public CCsDisasm<CMipsInsClass> {
public:
  CMicroMipsCDisasm(unsigned int mode = cs_mode::CS_MODE_MICRO +
                                        cs_mode::CS_MODE_BIG_ENDIAN)
      : CCsDisasm(cs_arch::CS_ARCH_MIPS, mode) {}
};

class C64MipsCDisasm : public CCsDisasm<CMipsInsClass> {
public:
  C64MipsCDisasm(unsigned int mode = cs_mode::CS_MODE_64 +
                                     cs_mode::CS_MODE_BIG_ENDIAN)
      : CCsDisasm(cs_arch::CS_ARCH_MIPS, mode) {}
};
