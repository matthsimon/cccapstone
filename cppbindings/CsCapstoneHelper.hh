#pragma once

#include <capstone.h>
#include <memory>

template<typename CsInsClass_t>
struct CS_INSN_HOLDER
{
	size_t Size;
	const void* Address;
	size_t Count;

	inline
	CsInsClass_t
	Instructions(
		size_t i
		) 
	{
		return *new CsInsClass_t(m_csh, m_csInstructions + i);
	}

	CS_INSN_HOLDER(
		csh csh,
		const void* address,
		size_t size,
		size_t baseAddr
		) : m_csh(csh),
			Address(address),
			Size(size),
			m_csInstructions(nullptr)
	{
		Count = cs_disasm(
			m_csh,
			static_cast<const unsigned char*>(address),
			size,
			baseAddr,
			0,
			&m_csInstructions);
	}

	~CS_INSN_HOLDER()
	{
		if (m_csInstructions)
			cs_free(m_csInstructions, Count);
	}

	void operator=(CS_INSN_HOLDER const&) = delete;
	CS_INSN_HOLDER(const CS_INSN_HOLDER &) = delete;

protected:
	template<typename CsInsClassTemp_t>
	friend class CCsDisasm;

	cs_insn* m_csInstructions;
	csh m_csh;
};
