#pragma once

#include <capstone.h>
#include "CsCapstoneHelper.hh"

//x86_insn_group, x86_reg, x86_op_type, x86_insn
template<typename InsGroup_t, typename Reg_t, typename Op_t, typename Ins_t>
class CCsIns
{
	csh m_csh;
	cs_insn* m_ins;

	void operator=(CCsIns const&) = delete;
	//CCsIns(const CCsIns &) = delete;//==> must be kicked out in the future, and CS_HANDLE not shared_ptr .. need redesign ...
public:
	CCsIns(
		csh csh,
		cs_insn* ins
		) : m_csh(csh),
			m_ins(ins)
	{
	}

	const cs_insn*
	operator->() const
	{
		return m_ins;
	}

	inline
	bool 
	IsInInsGroup(
		InsGroup_t groupId
		) const
	{
		return cs_insn_group(m_csh, m_ins, groupId);
	}

	inline
	bool 
	RegRead(
		Reg_t regId
		) const
	{
		return cs_reg_read(m_csh, m_ins, regId);
	}

	inline
	bool 
	RegWrite(
		Reg_t regId
		) const
	{
		return cs_reg_write(m_csh, m_ins, regId);
	}

	inline
	int
	OpcodeCount(
		Op_t opType
		) const
	{
		return cs_op_count(m_csh, m_ins, opType);
	}

	inline
	int
	OpcodeIndex(
		Op_t opType,
		unsigned int opcodePosition = 0
		) const
	{
		return cs_op_index(m_csh, m_ins, opType, opcodePosition);
	}

	inline
	const char* 
	RegName(
		Reg_t reg
		) const
	{
		return cs_reg_name(m_csh, reg);
	}

	inline
	const char* 
	InsName(
		Ins_t ins
		) const
	{
		return cs_insn_name(m_csh, ins);
	}

	static
	inline
	const char* 
	RegName(
		csh& cs,
		Reg_t reg
		) 
	{
		return cs_reg_name(cs, reg);
	}

	static
	inline
	const char* 
	InsName(
		csh& cs,
		Ins_t ins
		) 
	{
		return cs_insn_name(cs, ins);
	}
};
