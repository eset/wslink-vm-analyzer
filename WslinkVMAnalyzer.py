# -*- encoding: utf8 -*-
#
# Copyright (c) 2021-2022 ESET spol. s r.o.
# Author: Vladislav Hrčka <vladislav.hrcka@eset.com>
# See LICENSE file for redistribution.

from miasm.analysis.machine import Machine
from miasm.analysis.binary import Container
from miasm.core.locationdb import LocationDB
from miasm.ir.ir import IRBlock, AssignBlock
from miasm.ir.symbexec import SymbolicExecutionEngine, get_block
from miasm.arch.x86.regs import *
from miasm.expression.expression import *
from miasm.expression.simplifications import expr_simp, expr_simp_high_to_explicit
from miasm.analysis.simplifier import IRCFGSimplifierSSA
from collections import namedtuple
from binascii import hexlify
import logging

logger = logging.getLogger('VMAnalyzer')
logger.setLevel(logging.DEBUG)
logging.basicConfig(filename='vma.log', level=logging.DEBUG)

MySymbolicExecutionEngineState = namedtuple('MySymbolicExecutionEngineState', 'rel_regs symbols')


class MySymbolicExecutionEngine(SymbolicExecutionEngine):
    def __init__(self, virt_context, bs, relative_registers, *args, **kwargs):
        self.virt_context = virt_context
        self.bs = bs
        self.relative_registers = relative_registers
        super(MySymbolicExecutionEngine, self).__init__(*args, **kwargs)

    def get_state(self):
        symbols = super(MySymbolicExecutionEngine, self).get_state()
        return MySymbolicExecutionEngineState(self.relative_registers.copy(), symbols)

    def set_state(self, state):
        super(MySymbolicExecutionEngine, self).set_state(state.symbols)
        self.relative_registers = state.rel_regs

    def mem_read(self, expr):
        """Memory read wrapper for symbolic execution
        @expr_mem: ExprMem"""
        new_expr = self.symbols.read(expr)
        if new_expr != expr:
            return new_expr
        conc_expr = self._apply_relative_registers(expr)
        addr = None
        if conc_expr:
            addr = self.eval_expr_visitor(conc_expr.ptr)
        elif expr.ptr.is_int() and int(expr.ptr) < len(self.bs.bin):
            addr = expr.ptr
        if addr is not None and addr.is_int():
            size = expr.size // (self.lifter.attrib // 8)
            value = self.bs.getbytes(int(addr), size)
            res = ExprInt(int(hexlify(value[::-1]), 16), expr.size)
            return res
        return new_expr

    def _apply_relative_registers(self, expr):
        if expr.ptr in self.relative_registers:
            return expr.replace_expr(self.relative_registers)
        if expr.ptr.is_op('+') and \
                any(e in expr.ptr.args for e in self.relative_registers.keys()) and \
                any(e.is_int() for e in expr.ptr.args):
            return expr.replace_expr(self.relative_registers)
        return None


class NodeResult(object):
    def __init__(self):
        self.next_nodes = []
        self.assignments = None


class Node(object):
    state_ids = {}
    virt_cont = None
    loc_db = None
    symb_engine = None

    def __init__(self, addr, loc_key, init_symbols, depth, se_state=None):
        self.addr = addr
        self.loc_key = loc_key
        self.init_symbols = init_symbols
        self.depth = depth
        self.se_state = se_state

    def clear(self):
        self.se_state = None
        self.init_symbols = None

    def _update_context(self):
        context_symbs = self.virt_cont.get_updated_internal_context(Node.symb_engine)
        rel_regs = {self.virt_cont.vm_pc_symb: context_symbs[self.virt_cont.vm_pc_symb]}
        state = MySymbolicExecutionEngineState(rel_regs, self.init_symbols)
        Node.symb_engine.set_state(state)
        del context_symbs[self.virt_cont.vm_pc_symb]
        Node.symb_engine.eval_updt_assignblk(context_symbs)
        return Node.symb_engine.symbols.copy()

    def _get_next(self, next_addr, new_init_symbols=None, copy=False, initial=False):
        state_hash = Node.virt_cont.get_state_hash(Node.symb_engine)
        state_id = StateId(state_hash, next_addr)
        if state_id in Node.state_ids:
            logger.debug("matched addr %s to %s" % (str(next_addr), str(Node.state_ids[state_id].loc_key)))
            return Node.state_ids[state_id], False

        new_loc_key = Node.loc_db.add_location()
        init_symbols = self.init_symbols if new_init_symbols is None else new_init_symbols
        se_state = None if not copy else Node.symb_engine.get_state()
        depth = self.depth + 1 if not initial else 0
        cnt = Node(next_addr, new_loc_key, init_symbols, depth, se_state)
        Node.state_ids[state_id] = cnt
        return cnt, True

    def _get_next_new_instr(self, addr):
        new_init_symbols = self._update_context()
        return self._get_next(addr, new_init_symbols=new_init_symbols, initial=True)

    @staticmethod
    def _simp_compose(irdst):
        # ({0x40 0 8, FLAGS 8 64} & 0x40)?(0x20, 0x30) -> 0x30
        # https://github.com/cea-sec/miasm/issues/1381
        if not irdst.is_cond() or not irdst.cond.is_op('&') or not irdst.cond.args[0].is_compose():
            return irdst
        if not irdst.cond.args[0].args[0].is_int() or not irdst.cond.args[1].is_int():
            return irdst
        if len(bin(int(irdst.cond.args[1]))) - 2 > irdst.cond.args[0].args[0].size:
            return irdst
        if int(irdst.cond.args[1]) & int(irdst.cond.args[0].args[0]):
            return irdst.src1
        return irdst.src2

    def _apply_context_reg(self, irdst):
        # (RBP_init == 0x9)?(0x20, 0x30) -> 0x30
        # ({((((RBP_init + 0x1E) ^ (RBP_init + 0x58)) & ((RBP_init + 0x58) ^ 0x3A)) ... -> ExprInt(X)
        if Node.virt_cont.context_reg not in irdst.get_r():
            return irdst
        return self.symb_engine.eval_expr(
            irdst.replace_expr({Node.virt_cont.context_reg: Node.virt_cont.context_reg_val}))

    def _simp(self, irdst):
        context_irdst = self._apply_context_reg(irdst)
        comp_irdst = self._simp_compose(context_irdst)
        return comp_irdst

    def process_addr(self, next_addr):
        results = NodeResult()
        next_addr = self._simp(next_addr)
        if isinstance(next_addr, ExprInt):
            # There is only 1 possible path
            self.addr = next_addr
            results.next_nodes.append(self)
        elif isinstance(next_addr, ExprCond):
            # There are 2 possible paths, let's process both
            results.assignments = Node.virt_cont.get_irb_symbs(Node.symb_engine, self.init_symbols)
            cnt_right, is_new = self._get_next(next_addr.src2, copy=True)
            if is_new:
                results.next_nodes.append(cnt_right)
            cnt_left, is_new = self._get_next(next_addr.src1)
            if is_new:
                results.next_nodes.append(cnt_left)
            src1 = ExprLoc(cnt_left.loc_key, Node.symb_engine.lifter.attrib)
            src2 = ExprLoc(cnt_right.loc_key, Node.symb_engine.lifter.attrib)
            self.clear()
            results.assignments[Node.symb_engine.lifter.IRDst] = ExprCond(next_addr.cond, src1, src2)
        else:
            irdst = Node.virt_cont.get_next_instr(Node.symb_engine)
            if isinstance(irdst, ExprInt):
                # a new virtual instruction
                results.assignments = Node.virt_cont.get_irb_symbs(Node.symb_engine, self.init_symbols, skip_rsp=False)
                new_cnt, is_new = self._get_next_new_instr(irdst)
                if is_new:
                    results.next_nodes.append(new_cnt)
                self.clear()
                results.assignments[Node.symb_engine.lifter.IRDst] = ExprLoc(new_cnt.loc_key,
                                                                             Node.symb_engine.lifter.attrib)
            else:
                results.assignments = Node.virt_cont.get_irb_symbs(Node.symb_engine, self.init_symbols, True, False)
                results.assignments[Node.symb_engine.lifter.IRDst] = irdst
                logger.debug("The last irdst is: %s" % str(irdst))
        return results


class InitialNode(Node):
    def __init__(self, symb_engine, virt_cont, loc_db):
        addr = symb_engine.symbols[symb_engine.lifter.IRDst]
        loc_key = loc_db.add_location()
        symb_engine.eval_updt_assignblk(virt_cont.initial_concrete_symbs)

        state_hash = virt_cont.get_state_hash(symb_engine)
        Node.state_ids[StateId(state_hash, addr)] = loc_key
        Node.virt_cont = virt_cont
        Node.loc_db = loc_db
        Node.symb_engine = symb_engine
        super(InitialNode, self).__init__(addr, loc_key, symb_engine.symbols.copy(), 0)


StateId = namedtuple('StateId', 'hash addr')


class SymbolicCFG(object):
    def __init__(self, virt_cont, mdis, ir):
        self.mdis = mdis
        self.ir = ir
        self.ircfg = self.ir.new_ircfg()
        self.out_ircfg = self.ir.new_ircfg()
        self.virt_cont = virt_cont

    def process_symb_state(self, symb_engine, **kwargs):
        cnt = InitialNode(symb_engine, self.virt_cont, self.out_ircfg.loc_db)
        todo = [cnt]
        max_depth = kwargs.get("max_depth", 25)
        while todo:
            cnt = todo.pop()
            if cnt.depth == max_depth:
                logger.warning("Maximum depth has been reached at %s" % str(cnt.addr))
                break
            if cnt.se_state is not None:
                Node.symb_engine.set_state(cnt.se_state)
                cnt.se_state = None
            ir_block = get_block(self.ir, self.ircfg, self.mdis, cnt.addr)
            irdst = cnt.symb_engine.eval_updt_irblock(ir_block)
            next_addr = cnt.symb_engine.eval_expr(irdst)
            curr_addr = cnt.addr
            curr_vmpc = cnt.symb_engine.relative_registers[self.virt_cont.vm_pc_symb]
            while isinstance(next_addr, ExprLoc):
                addr = self.ircfg.loc_db.get_location_offset(next_addr.loc_key)
                if addr is not None:  # the instruction could have been translated into multiple IR blocks
                    next_addr = ExprInt(addr, next_addr.size)
                else:
                    ir_block = get_block(self.ir, self.ircfg, self.mdis, next_addr)
                    irdst = cnt.symb_engine.eval_updt_irblock(ir_block)
                    next_addr = cnt.symb_engine.eval_expr(irdst)

            result = cnt.process_addr(next_addr)
            todo.extend(result.next_nodes)
            if result.assignments:
                irb = IRBlock(self.out_ircfg.loc_db, cnt.loc_key, [AssignBlock(result.assignments)])
                logger.debug("addr: %s" % str(curr_addr))
                logger.debug("curr_vmpc: %s" % str(curr_vmpc))
                logger.debug(str(irb))
                logger.debug('\n')
                self.out_ircfg.add_irblock(irb)
        return self.out_ircfg


def is_below_rsp(symb_engine, expr, skip_rsp=False):
    if not expr.is_mem():
        return False
    diff = expr_simp(expr.ptr - symb_engine.symbols[RSP])
    if diff.is_int() and (skip_rsp or int(expr_simp(expr_is_signed_lower(diff, ExprInt(0, diff.size))))):
        return True
    return False


class VirtualContext(object):
    def __init__(self, context_reg, vm_pc_off_val, instr_table_off_val, concrete_registers=None, reloc=0):
        self.vm_pc_symb = ExprMem(context_reg[0] + vm_pc_off_val[0], vm_pc_off_val[1].size)
        self.vm_pc_val = vm_pc_off_val[1]
        self.instr_table_symb = ExprMem(context_reg[0] + instr_table_off_val[0], instr_table_off_val[1].size)
        self.instr_table_addr = instr_table_off_val[1]
        self.context_reg = context_reg[0]
        self.context_reg_val = context_reg[1]
        self.reloc = reloc

        self.initial_concrete_symbs = {}
        if concrete_registers:
            self.initial_concrete_symbs = {
                ExprMem(context_reg[0] + ExprInt(offset, context_reg[0].size), size): val
                for (offset, size), val in concrete_registers.items()}
        self.all_symbs = self.initial_concrete_symbs.keys() | {self.vm_pc_symb}

    def get_next_instr(self, symb_engine):
        symb_engine.relative_registers[self.instr_table_symb] = self.instr_table_addr
        res = symb_engine.eval_expr(symb_engine.symbols[symb_engine.lifter.IRDst])
        if res.is_int():
            res = expr_simp(res + ExprInt(self.reloc, res.size))
        del symb_engine.relative_registers[self.instr_table_symb]
        return res

    def get_irb_symbs(self, symb_engine, init_symbols, get_ids=False, skip_rsp=True):
        # skip_rsp is meant for pushes preceding conditional jumps that should be skipped since they can be popped later
        # get_ids is meant for the last virtual instruction to show mapping of the virtual registers back to the natives
        out_symbols = {}
        for expr, value in symb_engine.symbols.items():
            if init_symbols[expr] == value:
                continue
            if expr.is_id() and not get_ids:
                continue
            if is_below_rsp(symb_engine, expr, skip_rsp):
                continue
            if expr in self.all_symbs:
                continue
            if expr.is_mem() and expr.ptr.is_int() and int(expr.ptr) < len(symb_engine.bs.bin):
                continue
            out_symbols[expr] = value
        return out_symbols

    def get_updated_internal_context(self, symb_engine):
        out_symbols = {}
        for expr in self.all_symbs:
            value = symb_engine.eval_expr(symb_engine.symbols[expr].replace_expr(symb_engine.relative_registers))
            out_symbols[expr] = value
        return out_symbols

    def get_state_hash(self, symb_engine):
        return hash(symb_engine.relative_registers[self.vm_pc_symb])


class Wslink(object):
    def __init__(self, file_path, reloc=0):
        machine = Machine('x86_64')
        loc_db = LocationDB()
        cont = Container.from_stream(open(file_path, 'rb'), loc_db)
        bs = cont.bin_stream
        self.mdis = machine.dis_engine(bs, loc_db=loc_db)
        self.lifter = machine.lifter(loc_db)
        self.lifter_mc = machine.lifter_model_call(loc_db)
        self.reloc = reloc
        self.instr_table_addr = None
        self.obf_reg_offsets = None
        self.vm_base = None
        self.vm_pc_off = None
        self.instr_table_off = None

    def _read_val(self, addr, bit_size):
        value = self.mdis.bin_stream.getbytes(addr, bit_size)
        return value

    def _read_expr(self, addr, bit_size, rebase=0):
        value = self._read_val(addr, bit_size)
        expr = ExprInt(int(hexlify(value[::-1]), 16) + rebase, bit_size)
        return expr

    def _instr_offset_to_addr(self, init_instr_offset, instr_table_addr):
        size = self.lifter.attrib // 8
        return self._read_expr(init_instr_offset * size + instr_table_addr, self.lifter.attrib, self.reloc)

    def _get_conc_regs(self, base, offsets):
        regs = {}
        for val, size in offsets:
            rhs = self._read_expr(base + val, size)
            regs[(val, size)] = rhs
        return regs

    def process(self, vm_pc, init_instr_offset, opt=True):
        conc_regs = self._get_conc_regs(self.vm_base, self.obf_reg_offsets)
        virt_cont = VirtualContext((RBP_init, ExprInt(self.vm_base, 64)), (ExprInt(self.vm_pc_off, 64),
                                                                           ExprInt(vm_pc, 64)),
                                   (ExprInt(self.instr_table_off, 64), ExprInt(self.instr_table_addr, 64)),
                                   conc_regs, self.reloc)
        relative_registers = {virt_cont.vm_pc_symb: virt_cont.vm_pc_val}
        symb_engine = MySymbolicExecutionEngine(virt_cont, self.mdis.bin_stream, relative_registers, self.lifter,
                                                state=regs_init)
        init_addr = self._instr_offset_to_addr(init_instr_offset, self.instr_table_addr)
        symb_eval = SymbolicCFG(virt_cont, self.mdis, self.lifter)

        symb_engine.eval_updt_expr(ExprAssign(self.lifter.IRDst, init_addr))
        out_ircfg = symb_eval.process_symb_state(symb_engine)

        if opt:
            ssa_simp = IRCFGSimplifierSSA(self.lifter_mc)
            out_ircfg = ssa_simp.simplify(out_ircfg, out_ircfg.heads()[0])

        out_ircfg.simplify(expr_simp_high_to_explicit)
        open('vma.dot', 'w').write(out_ircfg.dot())
        # dot -Tsvg vma.dot -o vma.svg
