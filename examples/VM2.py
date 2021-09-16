# -*- encoding: utf8 -*-
#
# Copyright (c) 2021-2022 ESET spol. s r.o.
# Author: Vladislav Hrčka <vladislav.hrcka@eset.com>
# See LICENSE file for redistribution.

from WslinkVMAnalyzer import Wslink


class VM2(Wslink):
    def __init__(self, file_path, reloc=0):
        super().__init__(file_path, reloc)
        self.instr_table_addr = 0xf5e87
        self.obf_reg_offsets = {(0x70, 32), (0xb, 16), (0x94, 32), (0xA0, 32), (0x48, 32),
                                (0x103, 16), (0xfa, 32), (0x133, 32), (0xee, 32), (0x149, 16)}
        self.vm_base = 0
        self.vm_pc_off = 0x28
        self.instr_table_off = 0xa4


reloc = -0xf33f5
vma = VM2('extracted_vm.dmp')
first_virt_instr_in_table = 0x1f2189 + reloc
first_executed_virt_instr = 0x1fe661 + reloc
second_executed_virt_instr = 0x210D3E + reloc
third_executed_virt_instr = 0x1F4E38 + reloc
fourth_executed_virt_instr = 0x1F9C14 + reloc

vma.process(fourth_executed_virt_instr, 0x3f1)
