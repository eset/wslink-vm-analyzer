# -*- encoding: utf8 -*-
#
# Copyright (c) 2021-2022 ESET spol. s r.o.
# Author: Vladislav Hrčka <vladislav.hrcka@eset.com>
# See LICENSE file for redistribution.

from WslinkVMAnalyzer import Wslink


class VM1(Wslink):
    def __init__(self, file_path, reloc=0):
        super().__init__(file_path, reloc)
        self.instr_table_addr = 0x11de70
        self.obf_reg_offsets = {(0x8, 8), (0x11, 32), (0x26, 32), (0x60, 16), (0xbe, 32),
                                (0xd4, 32), (0x13b, 32), (0x147, 32), (0x107, 64),
                                (0xc2, 64), (0xae, 64), (0x3e, 8), (0x34, 8), (0x102, 8),
                                (0x35, 8), (0x3f, 64), (0x92, 64), (0x57, 8),
                                (0x1d, 8)}
        self.vm_base = 0xf9206
        self.vm_pc_off = 0x2c
        self.instr_table_off = 0xee


reloc = -0xf33f5
vma = VM1('extracted_vm.dmp', reloc)
first_executed_virt_instr = 0x21dbea + reloc
first_virt_instr_in_table = 0x21B4E0 + reloc
vma.process(first_executed_virt_instr, 0x19, opt=True)
