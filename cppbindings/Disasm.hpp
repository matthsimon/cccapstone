#pragma once

#include "CsCapstoneHelper.hh"

template <typename CsInsClass_t> class CCsDisasm {
protected:
  csh m_csh;
  cs_err m_err;

public:
  using Reg = typename CsInsClass_t::Reg;
  using Ins = typename CsInsClass_t::Ins;

  CCsDisasm(cs_arch arch, unsigned int mode) {
    m_err = cs_open(arch, static_cast<cs_mode>(mode), &m_csh);
  }

  ~CCsDisasm() { cs_close(&m_csh); }

  inline bool isOpen() { return m_err == CS_ERR_OK; }

  using InsHolder = CsInsnHolder<CsInsClass_t>;
  using InsHolderIter = CsInsnHolderIter<CsInsClass_t>;

  //////////////////////////////////////////////////////////////////////////
  // runtime opcode info
  //////////////////////////////////////////////////////////////////////////
  inline InsHolder disasm(const void *code, size_t size, size_t baseAddr = 0) {
    return InsHolder(m_csh, code, size, baseAddr);
  }

  inline InsHolderIter disasmIterator(const void *code, size_t size,
                                      size_t baseAddr = 0) {
    return InsHolderIter(m_csh, code, size, baseAddr);
  }

  inline cs_err getError() { return m_err; }

  inline unsigned int version(int *major = nullptr, int *minor = nullptr) {
    return cs_version(major, minor);
  }

  inline static const char *errToStr(cs_err err) { return cs_strerror(err); }

  inline std::string_view regName(Reg reg) const {
    return std::string_view(cs_reg_name(m_csh, reg));
  }

  inline std::string_view insName(Ins ins) const {
    return std::string_view(cs_insn_name(m_csh, ins));
  }

  //////////////////////////////////////////////////////////////////////////
  // cs capstone engine settings
  //////////////////////////////////////////////////////////////////////////

  /*
          cs_opt_value::CS_OPT_SYNTAX_DEFAULT = 0, // Default asm syntax
     (CS_OPT_SYNTAX). cs_opt_value::CS_OPT_SYNTAX_INTEL, // X86 Intel asm syntax
     - default on X86 (CS_OPT_SYNTAX). cs_opt_value::CS_OPT_SYNTAX_ATT,   // X86
     ATT asm syntax (CS_OPT_SYNTAX). cs_opt_value::CS_OPT_SYNTAX_NOREGNAME, //
     Prints register name with only number (CS_OPT_SYNTAX)

          http://capstone-engine.org/lang_c.html
  */
  inline bool setSyntax(cs_opt_value syntax) {
    return !cs_option(m_csh, cs_opt_type::CS_OPT_SYNTAX, syntax);
  }

  /*
          How detailed info in included per insn :

          cs_opt_value::CS_OPT_OFF //by default
          cs_opt_value::CS_OPT_ON
  */
  inline bool setDetail(cs_opt_value detailedInfo) {
    return !cs_option(m_csh, cs_opt_type::CS_OPT_DETAIL, detailedInfo);
  }

  /*
          change mode at runtime :

          cs_mode::CS_MODE_LITTLE_ENDIAN = 0,	// little endian mode (default
     mode) cs_mode::CS_MODE_ARM = 0,	// 32-bit ARM cs_mode::CS_MODE_16 = 1 <<
     1,	// 16-bit mode cs_mode::CS_MODE_32 = 1 << 2,	// 32-bit mode
          cs_mode::CS_MODE_64 = 1 << 3,	// 64-bit mode
          cs_mode::CS_MODE_THUMB = 1 << 4,	// ARM's Thumb mode, including
     Thumb-2 cs_mode::CS_MODE_MICRO = 1 << 4, // MicroMips mode (MIPS
     architecture) cs_mode::CS_MODE_N64 = 1 << 5, // Nintendo-64 mode (MIPS
     architecture) cs_mode::CS_MODE_V9 = 1 << 4, // SparcV9 mode (Sparc
     architecture) cs_mode::CS_MODE_BIG_ENDIAN = 1 << 31	// big endian
     mode

          http://capstone-engine.org/lang_c.html
  */
  inline bool setMode(cs_mode mode) {
    return !cs_option(m_csh, cs_opt_type::CS_OPT_MODE, mode);
  }

  /*
          possibility to redefining of mem mgr functions :

          void *malloc(size_t size);
          void *calloc(size_t nmemb, size_t size);
          void *realloc(void *ptr, size_t size);
          void  free(void *ptr);
          int   vsnprintf(char *str, size_t size, const char *format, va_list
     ap);

          http://capstone-engine.org/embed.html
  */
  inline bool setMemMgrFunc(cs_opt_mem &memMgrSetup) {
    return !cs_option(m_csh, cs_opt_type::CS_OPT_MEM,
                      reinterpret_cast<size_t>(&memMgrSetup));
  }

  /*
          what to do when hitting *broken* instruction

          cs_opt_value::CS_OPT_OFF = stop //by default
          cs_opt_value::CS_OPT_ON = continue (+ write .byte prefix)

          http://capstone-engine.org/skipdata.html
  */
  inline bool setSkipData(cs_opt_value skipData) {
    return !cs_option(m_csh, cs_opt_type::CS_OPT_SKIPDATA, skipData);
  }

  /*
          Define our mneomic alternative to .byte or/and callback at *broken*
     instructions

          cs_skipdata_cb_t callback :
                  return 0 if want to stop disassembling
                  return <size> how many bytes to skip (cover by mnemonic)

          -> example :
     https://github.com/aquynh/capstone/blob/next/tests/test_skipdata.c
          http://capstone-engine.org/skipdata.html
  */
  inline bool setSkipDataCallback(cs_opt_skipdata &dataCallbackSetup) {
    if (!setSkipData(CS_OPT_ON))
      return false;
    return !cs_option(m_csh, cs_opt_type::CS_OPT_SKIPDATA_SETUP,
                      reinterpret_cast<size_t>(&dataCallbackSetup));
  }
};
