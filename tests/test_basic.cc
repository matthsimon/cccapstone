extern "C" {
    #include <capstone.h>
}

#define BOOST_TEST_MODULE basic
#include <boost/test/included/unit_test.hpp>
#define BOOST_MPL_CFG_NO_PREPROCESSED_HEADERS
#define BOOST_MPL_LIMIT_LIST_SIZE 30
#include <boost/mpl/list.hpp>
#include <climits>

#include "ArmDisasm.hh"
#include "MipsDisasm.hh"
#include "PPCDisasm.hh"
#include "SparcDisasm.hh"
#include "SystemZDisasm.hh"
#include "X86Disasm.hh" 
#include "XCoreDisasm.hh"

template <class T>
struct PlatformTest {
        using Disasm = T;
        static constexpr std::string_view descr = "";
        static constexpr std::string_view code = "";
        static const cs_opt_value syntax = CS_OPT_SYNTAX_DEFAULT;
        static const unsigned int mode = UINT_MAX;
};

struct CX86Disasm16Test : public PlatformTest<CX86Disasm16> {
        static constexpr std::string_view descr = "X86 16bit (Intel syntax)";
        static constexpr std::string_view code = "\x8d\x4c\x32\x08\x01\xd8\x81\xc6\x34\x12\x00\x00";
};

struct CX86Disasm86AttTest : public PlatformTest<CX86Disasm86> {
    static constexpr std::string_view descr = "X86 32bit (ATT syntax)";
    static constexpr std::string_view code = "\x8d\x4c\x32\x08\x01\xd8\x81\xc6\x34\x12\x00\x00";
    static const cs_opt_value syntax = CS_OPT_SYNTAX_ATT;
};

struct CX86Disasm86IntelTest : public PlatformTest<CX86Disasm86> {
    static constexpr std::string_view descr = "X86 32bit (Intel syntax)";
    static constexpr std::string_view code = "\x8d\x4c\x32\x08\x01\xd8\x81\xc6\x34\x12\x00\x00";
};

struct CX86Disasm64Test : public PlatformTest<CX86Disasm64> {
    static constexpr std::string_view descr = "X86 64 (Intel syntax)";
    static constexpr std::string_view code = "\x55\x48\x8b\x05\xb8\x13\x00\x00";
};

struct ARMDisasmTest : public PlatformTest<CArmDisasm> {
    static constexpr std::string_view descr = "ARM";
    static constexpr std::string_view code = "\xED\xFF\xFF\xEB\x04\xe0\x2d\xe5\x00\x00\x00\x00\xe0\x83\x22\xe5\xf1\x02\x03\x0e\x00\x00\xa0\xe3\x02\x30\xc1\xe7\x00\x00\x53\xe3";
    static const unsigned int mode = CS_MODE_ARM;
};

struct ARMThumbDisasmTest : public PlatformTest<CArmDisasm> {
    static constexpr std::string_view descr = "THUMB";
    static constexpr std::string_view code = "\x70\x47\xeb\x46\x83\xb0\xc9\x68";
};

struct ARMThumb2DisasmTest : public PlatformTest<CArmDisasm> {
    static constexpr std::string_view descr = "THUMB-2";
    static constexpr std::string_view code = "\x4f\xf0\x00\x01\xbd\xe8\x00\x88\xd1\xe8\x00\xf0";
};

struct ARMThumbMClassDisasmTest : public PlatformTest<CArmDisasm> {
    static constexpr std::string_view descr = "THUMB-MClass";
    static constexpr std::string_view code = "\xef\xf3\x02\x80";
    static const unsigned int mode = CS_MODE_THUMB + CS_MODE_MCLASS;
};

struct ARMCortexDisasmTest : public PlatformTest<CArmDisasm> {
    static constexpr std::string_view descr = "ARM: Cortex-A16 + NEON";
    static constexpr std::string_view code = "\x10\xf1\x10\xe7\x11\xf2\x31\xe7\xdc\xa1\x2e\xf3\xe8\x4e\x62\xf3";
    static const unsigned int mode = CS_MODE_ARM;
};

struct ARMV8DisasmTest : public PlatformTest<CArmDisasm> {
    static constexpr std::string_view descr = "ARM-V8";
    static constexpr std::string_view code = "\xe0\x3b\xb2\xee\x42\x00\x01\xe1\x51\xf0\x7f\xf5";
    static const unsigned int mode = CS_MODE_ARM + CS_MODE_V8;
};

struct ARM64DisasmTest : public PlatformTest<CArmDisasm64> {
    static constexpr std::string_view descr = "ARM-64";
    static constexpr std::string_view code = "\x21\x7c\x02\x9b\x21\x7c\x00\x53\x00\x40\x21\x4b\xe1\x0b\x40\xb9";
};

struct Mips32DisasmTest : public PlatformTest<CMicroMipsCDisasm> {
    static constexpr std::string_view descr = "MIPS-32 (Big-endian)";
    static constexpr std::string_view code = "\x0C\x10\x00\x97\x00\x00\x00\x00\x24\x02\x00\x0c\x8f\xa2\x00\x00\x34\x21\x34\x56";
    static const unsigned int mode = CS_MODE_MIPS32 + CS_MODE_BIG_ENDIAN;
};

struct Mips64ELDisasmTest : public PlatformTest<C64MipsCDisasm> {
    static constexpr std::string_view descr = "MIPS-64-EL (Little-endian)";
    static constexpr std::string_view code = "\x56\x34\x21\x34\xc2\x17\x01\x00";
    static const unsigned int mode = CS_MODE_MIPS64 + CS_MODE_LITTLE_ENDIAN;
};

struct Mips32R6MDisasmTest : public PlatformTest<CMicroMipsCDisasm> {
    static constexpr std::string_view descr = "MIPS-32R6 | Micro (Big-endian)";
    static constexpr std::string_view code = "\x00\x07\x00\x07\x00\x11\x93\x7c\x01\x8c\x8b\x7c\x00\xc7\x48\xd0";
    static const unsigned int mode = CS_MODE_MIPS32R6 + CS_MODE_MICRO + CS_MODE_BIG_ENDIAN;
};

struct Mips32R6DisasmTest : public PlatformTest<CMicroMipsCDisasm> {
    static constexpr std::string_view descr = "MIPS-32R6 (Big-endian)";
    static constexpr std::string_view code = "\xec\x80\x00\x19\x7c\x43\x22\xa0";
    static const unsigned int mode = CS_MODE_MIPS32R6 + CS_MODE_BIG_ENDIAN;
};

struct PPCDisasmTest : public PlatformTest<CPPCDisasm> {
    static constexpr std::string_view descr = "PPC-64";
    static constexpr std::string_view code = "\x80\x20\x00\x00\x80\x3f\x00\x00\x10\x43\x23\x0e\xd0\x44\x00\x80\x4c\x43\x22\x02\x2d\x03\x00\x80\x7c\x43\x20\x14\x7c\x43\x20\x93\x4f\x20\x00\x21\x4c\xc8\x00\x21";
};

struct PPCNoRegDisasmTest : public PlatformTest<CPPCDisasm> {
    static constexpr std::string_view descr = "PPC-64, print register with number only";
    static constexpr std::string_view code = "\x80\x20\x00\x00\x80\x3f\x00\x00\x10\x43\x23\x0e\xd0\x44\x00\x80\x4c\x43\x22\x02\x2d\x03\x00\x80\x7c\x43\x20\x14\x7c\x43\x20\x93\x4f\x20\x00\x21\x4c\xc8\x00\x21";
    static const cs_opt_value syntax = CS_OPT_SYNTAX_NOREGNAME;
};

struct SparcDisasmTest : public PlatformTest<CSparcDisasm> {
    static constexpr std::string_view descr = "Sparc";
    static constexpr std::string_view code = "\x80\xa0\x40\x02\x85\xc2\x60\x08\x85\xe8\x20\x01\x81\xe8\x00\x00\x90\x10\x20\x01\xd5\xf6\x10\x16\x21\x00\x00\x0a\x86\x00\x40\x02\x01\x00\x00\x00\x12\xbf\xff\xff\x10\xbf\xff\xff\xa0\x02\x00\x09\x0d\xbf\xff\xff\xd4\x20\x60\x00\xd4\x4e\x00\x16\x2a\xc2\x80\x03";
};

struct SparcV9DisasmTest : public PlatformTest<CSparcV9Disasm> {
    static constexpr std::string_view descr = "SparcV9";
    static constexpr std::string_view code = "\x81\xa8\x0a\x24\x89\xa0\x10\x20\x89\xa0\x1a\x60\x89\xa0\x00\xe0";
};

struct SystemZDisasmTest : public PlatformTest<CSystemZCDisasm> {
    static constexpr std::string_view descr = "SystemZ";
    static constexpr std::string_view code = "\xed\x00\x00\x00\x00\x1a\x5a\x0f\x1f\xff\xc2\x09\x80\x00\x00\x00\x07\xf7\xeb\x2a\xff\xff\x7f\x57\xe3\x01\xff\xff\x7f\x57\xeb\x00\xf0\x00\x00\x24\xb2\x4f\x00\x78";
};

struct XCoreDisasmTest : public PlatformTest<CXCoreCDisasm> {
    static constexpr std::string_view descr = "XCore";
    static constexpr std::string_view code = "\xfe\x0f\xfe\x17\x13\x17\xc6\xfe\xec\x17\x97\xf8\xec\x4f\x1f\xfd\xec\x37\x07\xf2\x45\x5b\xf9\xfa\x02\x06\x1b\x10";
};

using DisasmTypes = boost::mpl::list<CX86Disasm16Test, CX86Disasm86IntelTest, CX86Disasm86AttTest, CX86Disasm64Test,
                                     ARMDisasmTest, ARMThumbDisasmTest, ARMThumb2DisasmTest, ARMThumbMClassDisasmTest,
                                     ARMCortexDisasmTest, ARMV8DisasmTest, ARM64DisasmTest, Mips32DisasmTest, Mips64ELDisasmTest,
                                     Mips32R6MDisasmTest, Mips32R6DisasmTest, PPCDisasmTest, PPCNoRegDisasmTest, SparcDisasmTest,
                                     SparcV9DisasmTest, SystemZDisasmTest, XCoreDisasmTest>;

BOOST_AUTO_TEST_SUITE(BasicSuite);

BOOST_AUTO_TEST_CASE_TEMPLATE(test_basic, DisasmTest, DisasmTypes) {
    typename DisasmTest::Disasm dis;
    BOOST_REQUIRE(dis.isOpen());

    if (DisasmTest::syntax != CS_OPT_SYNTAX_DEFAULT) {
        BOOST_REQUIRE(dis.setSyntax(DisasmTest::syntax));
    }

    if (DisasmTest::mode != UINT_MAX) {
        BOOST_REQUIRE(dis.setMode(static_cast<cs_mode>(DisasmTest::mode)));
    }

    auto insn = dis.disasm(DisasmTest::code.data(), DisasmTest::code.size());
    int counter = 0;
    for (auto& i : insn) {
        ++counter;
    }

    BOOST_CHECK_EQUAL(insn.count(), counter);
}

BOOST_AUTO_TEST_CASE_TEMPLATE(test_basic_iter, DisasmTest, DisasmTypes) {
    typename DisasmTest::Disasm dis;
    BOOST_REQUIRE(dis.isOpen());

    if (DisasmTest::syntax != CS_OPT_SYNTAX_DEFAULT) {
        BOOST_REQUIRE(dis.setSyntax(DisasmTest::syntax));
    }

    if (DisasmTest::mode != UINT_MAX) {
        BOOST_REQUIRE(dis.setMode(static_cast<cs_mode>(DisasmTest::mode)));
    }

    auto insnIt = dis.disasmIterator(DisasmTest::code.data(), DisasmTest::code.size());
    for (auto& i : insnIt) {
        continue;
    }
}

BOOST_AUTO_TEST_SUITE_END()
