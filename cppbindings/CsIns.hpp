#pragma once

#include "CsCapstoneHelper.hh"
#include <capstone.h>

// x86_insn_group, x86_reg, x86_op_type, x86_insn
template <typename InsGroup_t, typename Reg_t, typename Op_t, typename Ins_t>
class CCsIns {
  csh m_csh;
  InstructionPtr m_ins;

public:
  using Reg = Reg_t;
  using Ins = Ins_t;
  CCsIns(csh csh, InstructionPtr ins) : m_csh(csh), m_ins(std::move(ins)) {}
  ~CCsIns() {
    // Do not let unique_ptr call deleter on the instruction, the default
    // allocator will cause free error.
    m_ins.release();
  }
  CCsIns(const CCsIns &) = delete;
  CCsIns(CCsIns &&ins) : m_csh(ins.m_csh), m_ins(ins.m_ins.release()) {}

  const cs_insn *operator->() const { return m_ins.get(); }
  cs_insn *get() { return m_ins.get(); }

  inline bool isInInsGroup(InsGroup_t groupId) const {
    return cs_insn_group(m_csh, m_ins.get(), groupId);
  }

  inline bool regRead(Reg_t regId) const {
    return cs_reg_read(m_csh, m_ins.get(), regId);
  }

  inline bool regWrite(Reg_t regId) const {
    return cs_reg_write(m_csh, m_ins.get(), regId);
  }

  inline int opcodeCount(Op_t opType) const {
    return cs_op_count(m_csh, m_ins.get(), opType);
  }

  inline int opcodeIndex(Op_t opType, unsigned int opcodePosition = 1) const {
    return cs_op_index(m_csh, m_ins.get(), opType, opcodePosition);
  }
};
