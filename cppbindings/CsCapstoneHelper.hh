#pragma once

#include <capstone.h>
#include <memory>
#include <vector>

using InstructionPtr = std::unique_ptr<cs_insn>;

template <typename CsInsClass_t> class CsInsnHolder {
public:
  using iterator = typename std::vector<CsInsClass_t>::iterator;

  inline CsInsClass_t &operator[](size_t i) { return m_csInstructions[i]; }

  CsInsnHolder(csh csh, const void *address, size_t size, size_t baseAddr)
      : m_csh(csh), m_address(address), m_size(size) {

    cs_insn *instrs;
    m_count = cs_disasm(m_csh, static_cast<const uint8_t *>(address), size,
                        baseAddr, 0, &instrs);

    for (size_t i = 0; i < m_count; ++i) {
      m_csInstructions.emplace_back(m_csh, InstructionPtr(instrs + i));
    }
  }

  ~CsInsnHolder() {
    if (!m_csInstructions.empty())
      cs_free(m_csInstructions[0].get(), m_count);
  }

  inline size_t size() const { return m_size; }

  inline size_t count() const { return m_count; }

  inline iterator begin() { return m_csInstructions.begin(); }

  inline iterator end() { return m_csInstructions.end(); }

protected:
  size_t m_size;
  const void *m_address;
  size_t m_count;

  std::vector<CsInsClass_t> m_csInstructions;
  csh m_csh;
};

template <typename CsInsClass_t> class CsInsnIterator {
public:
  const uint8_t *code;
  size_t size;
  uint64_t address;
  CsInsClass_t insn;

  using reference = CsInsnIterator<CsInsClass_t> &;

  CsInsnIterator(csh handle, const uint8_t *code, size_t size, size_t address,
                 bool fetching = true)
      : m_csh(handle), code(code), size(size), address(address),
        insn(handle, InstructionPtr(cs_malloc(handle))) {
    if (fetching)
      m_fetching = cs_disasm_iter(m_csh, &code, &size, &address, insn.get());
    else
      m_fetching = false;
  }

  ~CsInsnIterator() { cs_free(insn.get(), 1); }

  CsInsnIterator(const reference other) = delete;
  reference operator=(const reference other) = delete;

  reference operator++() {
    m_fetching = cs_disasm_iter(m_csh, &code, &size, &address, insn.get());
    return *this;
  }

  reference operator*() { return *this; }

  reference operator->() { return *this; }

  bool operator==(const reference other) const {
    return m_csh == other.m_csh &&
           (((m_fetching == other.m_fetching) && (m_fetching == false)) ||
            (code == other.code && address == other.address));
  }

  bool operator!=(const reference other) const { return !(*this == other); }

private:
  csh m_csh;
  bool m_fetching;
};

template <typename CsInsClass_t> class CsInsnHolderIter {
public:
  using iterator = CsInsnIterator<CsInsClass_t>;

  CsInsnHolderIter(csh csh, const void *code, size_t size, size_t baseAddr)
      : m_csh(csh), m_code(code), m_size(size), m_baseAddr(baseAddr) {}

  inline iterator begin() {
    return iterator(m_csh, static_cast<const uint8_t *>(m_code), m_size,
                    m_baseAddr);
  }

  inline iterator end() { return iterator(m_csh, nullptr, 0, 0, false); }

protected:
  csh m_csh;
  const void *m_code;
  size_t m_size;
  size_t m_baseAddr;
};
