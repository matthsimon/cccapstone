cccapstone
==========

c++ bindings for capstone disasembly framework (http://www.capstone-engine.org/ - https://github.com/aquynh/capstone)


**1. clone all (bindings & capstone as well)**

    git clone --recursive https://github.com/zer0mem/cccapstone.git

**2. basic settings**

    1. add to Additional include directories capstone include : $(SolutionDir)/cccapstone/capstone/include
   
    2. OPTIONAL (but not mandatory) include c++ bindings to source / header 3rdparty files
        > x86 example :
        --> \cccapstone\cppbindings\{ CsCapstoneHelper.hh, CsIns.hpp, Disasm.hpp, X86Disasm.hh }
        --> \cccapstone\capstone\include\capstone.h
    

**----------------------------------------------------------------------------------------**

**3. examples (intel x86 - x64)**
                
    /*
      f.e. for arm (vice versa with other architectures) can be 
           capstone disassembler created in some ways : 
        
        #include <cccapstone/cppbindings/ArmDisasm.hh>
           
      1. use predefined wrapper
        CArmDisasm64 dis;
                            
      2. use direct wrapper above c implementation
        auto dis = CCsDisasm<CArm64InsClass>(
            cs_arch::CS_ARCH_ARM64,
            cs_mode::CS_MODE_ARM + cs_mode::CS_MODE_BIG_ENDIAN);
    */
    
    CX86Disasm64 dis; // define disasembler by current needs. 
                      // cccapstone/cppbindings/<ARCHITECTURE>Disasm.hh for more available bindings
      
    //check if no error occured
    if (dis.isOpen())
    	return;
    	
    //set how deep should capstone reverse instruction
    dis.setDetail(cs_opt_value::CS_OPT_ON);

    //set syntax for output disasembly string
    dis.setSyntax(cs_opt_value::CS_OPT_SYNTAX_INTEL);
    
    //*OPTIONAL* - set callback, when is encountered data - not resolved code -
    dis.setSkipDataCallback(cs_opt_skipdata{ 
                                ".UNKOWNBYTES : ", 
                                SkipDataCallback, 
                                nullptr 
                                });
    
    //for more settings see cccapstone/cppbindings/Disasm.hpp
    
    //process disasembling
    auto insn = dis.Disasm(code, size);
    //check if disassembling succesfull
    if (!insn.count())
    	return;
    
    //print basic info
    for (auto& i : insn)
      printf("-> 0x%p:\t%s\t%s\n", i.address, i.mnemonic, i.op_str);
    
    //how to gather advanced info is by example in debug-print function 
    --> print_insn_detail (https://github.com/aquynh/capstone/blob/master/tests/test_x86.c)
    
    //in future in capstone will be possible also filtering group of instructions (and far more .. :)
    if (insn[i].isInInsGroup(x86_insn_group::X86_GRP_JUMP))
        printf("\nControl Flow change at : %p", insn->Instructions(i).address);
    
    
    
