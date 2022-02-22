#!/usr/bin/env python

import angr
import monkeyhex
import sys
import IPython

file_path = "otaApp-1.4.2.bin"
file_path2 = "otaApp-1.4.4.bin"
main_opts = {
    'backend': 'blob',
    'arch': 'ARMCortexM',
    'thumb': True,
    'base_addr': 0x20004000,
    'entry_point': 0x2001DA49
}


main_opts2 = {
    'backend': 'blob',
    'arch': 'ARMCortexM',
    'thumb': True,
    'base_addr': 0x20004000,
    'entry_point': 0x2001d619
}

def init_state(state):
    state.regs.r0 = 0
    state.regs.r1 = 0
    state.regs.r2 = 0
    state.regs.r3 = 0
    state.regs.r4 = 0
    state.regs.r5 = 0
    state.regs.r6 = 0
    state.regs.r7 = 0
    state.regs.r8 = 0
    state.regs.r9 = 0
    state.regs.r10 = 0
    state.regs.r11 = 0
    state.regs.r12 = 0
    # state.regs.sp
    # state.regs.lr
    # state.regs.pc



def printStateRegs(state): 
    arm_dict = {'r0':state.regs.r0, 'r1':state.regs.r1, 
'r2':state.regs.r2, 'r3':state.regs.r3, 'r4':state.regs.r4, 
'r5':state.regs.r5, 'r6':state.regs.r6, 'r7':state.regs.r7, 
'r8':state.regs.r8, 'r9':state.regs.r9, 'r10':state.regs.r10, 
'r11':state.regs.r11, 'r12':state.regs.r12, 'sp':state.regs.sp, 
'lr':state.regs.lr, 'pc':state.regs.pc, 'constraints': state.solver.constraints} 
    print(arm_dict)

def symbolic_execution():
    proj = angr.Project(file_path, load_options={
                        'auto_load_libs': False, 'main_opts': main_opts})
    cfg = proj.analyses.CFGFast()
    proj.analyses.BoyScout()
    proj2 = angr.Project(file_path2, load_options={
        'auto_load_libs': False, 'main_opts': main_opts2})
    cfg2 = proj2.analyses.CFGFast()
    proj2.analyses.BoyScout()    

    IPython.embed()

    # func_addrA = 0x20014ce9
    func_addrA = 0x20009675

    start_state = proj.factory.blank_state(addr = func_addrA, add_options={angr.options.NO_SYMBOLIC_JUMP_RESOLUTION, angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY, angr.options.UNDER_CONSTRAINED_SYMEXEC, angr.options.CALLLESS})

    func_addrB = 0x200148d5
    start_state2 = proj.factory.blank_state(addr = func_addrB, add_options={angr.options.NO_SYMBOLIC_JUMP_RESOLUTION, angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY, angr.options.UNDER_CONSTRAINED_SYMEXEC})
    

    init_state(start_state)
    simgr = proj.factory.simulation_manager(start_state, save_unconstrained=True)
    simgr2 = proj2.factory.simulation_manager(start_state2, save_unconstrained=True)
    
    print("blocks print")
    proj.factory.block(func_addrA).pp()
    proj2.factory.block(func_addrB).pp()
    # IPython.embed()

    simgr.run()
    # simgr.explore(find=0x200096a7)
    # simgr2.explore(find=0x200148db)
    IPython.embed()

    for item in cfg.kb.functions.items():
        print(item)


if __name__ == '__main__':
    symbolic_execution()

# printStateRegs(simgr.active[0])
proj.factory.block(0x20014cec).pp()



func_addrA = 0x2000ba99
start_state = proj.factory.blank_state(addr = func_addrA, add_options={angr.options.NO_SYMBOLIC_JUMP_RESOLUTION, angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY, angr.options.UNDER_CONSTRAINED_SYMEXEC, angr.options.CALLLESS})  
init_state(start_state)
simgr = proj.factory.simulation_manager(start_state, save_unconstrained=True)
proj.factory.block(func_addrA).pp()
# simgr.step(num_inst=1)
simgr.explore(find=0x2000bb29)


simgr.step(num_inst=1)
printStateRegs(simgr.active[0])




