from miasm.analysis.machine import Machine
from miasm.ir.symbexec import SymbolicExecutionEngine
from miasm.expression.expression import ExprCond, ExprInt, ExprOp, ExprLoc
from miasm.expression.simplifications import expr_simp
from miasm.arch.x86.regs import *
from miasm.analysis.binary import Container
import r2pipe
import sys

STDP = 0
CNDP1 = 1
CNDP0 = 2
CNDP2 = 3
CNDP3 = 4


def get_address(loc_db, loc_key):
    return loc_db.get_location_offset(loc_key)


def get_loc_key_at(loc_db, address):
    return loc_db.get_offset_location(address)


def get_node_from_loc_key(nodes, loc_key):
    return [_node for _node in nodes if _node.loc_key == loc_key][0]


def get_state_register(asmcfg, loc_key):
    asmblock = asmcfg.loc_key_to_block(loc_key)
    for line in asmblock.lines:
        if line.name == 'MOV' and isinstance(line.args[1], ExprInt) and \
                isinstance(line.args[0], ExprId):
            return line.args[0]
    return None


def ignore_call_results(expr_simp, expr):
    if expr.op == 'call_func_ret' or expr.op == 'call_func_stack':
        return ExprInt(0, 32)
    return expr


def fix_func_cfg(filename, to_patch_offsets):
    r2 = r2pipe.open(filename, ["-w"])
    r2.cmd("aaa")
    to_patch_offsets.sort(key=lambda tup: tup[0])

    def clean_block():
        r2.cmd("so +1")
        current_addr = int(r2.cmdj("?jv $$")["uint32"])
        blocks = r2.cmdj("abj")

        for block in blocks:
            if block["addr"] < current_addr <= block["addr"] + block["size"]:
                block_end_addr = block["addr"] + block["size"]
                for _ in range(block_end_addr - current_addr):
                    r2.cmd("wa nop")
                    r2.cmd("so +1")

    for n, offset in enumerate(to_patch_offsets):
        r2.cmd("s %s" % hex(offset[0]))

        if offset[2] == STDP:
            r2.cmd("so -1")
            r2.cmd("wa jmp %s" % hex(offset[1]))

        elif offset[2] == CNDP1:
            r2.cmd("so -1")
            r2.cmd("so -1")
            r2.cmd("so -1")
            r2.cmd("wa test eax, eax")
            r2.cmd("so +1")
            r2.cmd("wa jz %s" % hex(offset[1]))
            r2.cmd("so +1")

            elm = [x for x in to_patch_offsets if x[2] == CNDP0 and x[0] == offset[0]][0]
            r2.cmd("wa jmp %s" % hex(elm[1]))

        elif offset[2] == CNDP2:
            r2.cmd("wa jz %s" % hex(offset[1]))
            r2.cmd("so +1")
            elm = [x for x in to_patch_offsets if x[2] == CNDP3 and x[0] == offset[0]][0]
            r2.cmd("wa jmp %s" % hex(elm[1]))

        clean_block()


def get_assignblock_for_state(ircfg, ir_arch, symbols_init, state_register, state):
    referenced_blocks = []

    for cfgnode in ircfg.nodes():
        irblock = ircfg.get_block(cfgnode)
        if not irblock:
            print('[!] Could not get IRBLOCK!')
            sys.exit()
        if len(irblock.assignblks) == 1:
            _next_addr = irblock.dst
        else:
            _symbolic_engine = SymbolicExecutionEngine(ir_arch, symbols_init)
            _next_addr = _symbolic_engine.run_block_at(ircfg, get_address(ircfg.loc_db, cfgnode))
            if _next_addr == None:
                continue
            _next_addr = expr_simp(_next_addr)

        if isinstance(_next_addr, ExprCond) and \
                isinstance(_next_addr.cond, ExprOp) and \
                _next_addr.cond.op == '==':
            args = _next_addr.cond

            while not isinstance(args.args[0], ExprId):
                if hasattr(args, 'args'):
                    args = args.args[0]

                    if not isinstance(args, ExprOp):
                        break

            if hasattr(args, 'args') and \
                    args.args[0] in (state_register, symbols_init[state_register]) and \
                    args.args[1] == state:

                block = ircfg.get_block(cfgnode)
                if hasattr(block.dst.cond, 'op') and block.dst.cond.op in ('CC_S>'):
                    dst = get_address(ircfg.loc_db, block.dst.src2.loc_key)
                    next_block = ircfg.get_block(dst)
                    dst = get_address(ircfg.loc_db, next_block.dst.src1.loc_key)
                else:
                    dst = get_address(ircfg.loc_db, block.dst.src1.loc_key)

                referenced_block = ircfg.get_block(dst)
                referenced_blocks.append(referenced_block)
    return referenced_blocks


def process_blocks_for_patches(node, blocks, ircfg, patches, nodes_to_walk, state=None, is_conditional=False):
    for rblock in blocks:
        block = ircfg.get_block(rblock.loc_key)
        sblock = ircfg.get_block(node)

        if not block:
            print('[!] Could not get IRBLOCK!')
            sys.exit()

        if isinstance(block.dst, ExprCond):
            src = sblock.assignblks[-1].instr.offset

            if hasattr(block.dst.cond, 'op') and block.dst.cond.op == 'CC_S>':
                dst = get_address(ircfg.loc_db, block.dst.src2.loc_key)
                next_block = ircfg.get_block(dst)
                dst = get_address(ircfg.loc_db, next_block.dst.src1.loc_key)
            else:
                dst = get_address(ircfg.loc_db, block.loc_key)

            if block.dst.src1.loc_key not in nodes_to_walk:
                nodes_to_walk.append(block.dst.src1.loc_key)

            if state and not is_conditional:
                patches.add((src, dst, CNDP0))
            elif state and is_conditional:
                patches.add((src, dst, CNDP1))
            else:
                patches.add((src, dst, STDP))

        else:
            src = sblock.assignblks[-1].instr.offset
            dst = get_address(ircfg.loc_db, block.loc_key)

            if block.loc_key not in nodes_to_walk:
                nodes_to_walk.append(block.loc_key)

            if state and not is_conditional:
                patches.add((src, dst, CNDP0))
            elif state and is_conditional:
                patches.add((src, dst, CNDP1))
            else:
                patches.add((src, dst, STDP))


def scan_function_for_state(asmcfg, state_register, subj_reg):
    for asmblock in sorted(asmcfg.blocks, key=lambda x: x.loc_key):
        for line in asmblock.lines:
            if line.name == 'MOV' and line.args[0] == subj_reg and isinstance(line.args[1], ExprInt):
                for _asmblock in asmcfg.blocks:
                    for _line in _asmblock.lines:
                        if _line.name == "CMP" and _line.args[1] == line.args[1] and\
                                _line.args[0] == state_register:
                                return _line.args[1]
    return False


def resolve_offsets(state_register, asmcfg, ircfg, ir_arch):
    patches = set()
    nodes_to_walk = list(ircfg.nodes())

    symbols_init = dict()
    for i, r in enumerate(all_regs_ids):
        symbols_init[r] = all_regs_ids_init[i]

    expr_simp.enable_passes({ExprOp: [ignore_call_results]})

    for node in nodes_to_walk:
        irblock = ircfg.get_block(node)
        if not irblock:
            print('[-] Could not get IRBLOCK!')
            sys.exit()

        if len(irblock.assignblks) == 1:
            if irblock.assignblks[0].instr.name == "CMOVNZ" and irblock.assignblks[0].instr.args[0] == state_register:
                temp_reg1 = irblock.assignblks[0].instr.args[0]
                temp_reg2 = irblock.assignblks[0].instr.args[1]

                state1 = None
                state2 = None

                previous_block = ircfg.get_block(ircfg.predecessors(node)[0])
                for line in previous_block.assignblks:
                    if line.instr.name == 'MOV' and \
                            line.instr.args[0] in (temp_reg1, temp_reg2) and isinstance(line.instr.args[1], ExprInt):
                        if line.instr.args[0] == state_register:
                            state1 = line.instr.args[1]
                        else:
                            state2 = line.instr.args[1]
                    if state1 and state2:
                        break

                # compiler shenanigans. state missing is not initialised in current bblk. search function for it
                if not state1:
                    state1 = scan_function_for_state(asmcfg, state_register, temp_reg1)
                elif not state2:
                    state2 = scan_function_for_state(asmcfg, state_register, temp_reg2)

                blocks1 = get_assignblock_for_state(ircfg, ir_arch, symbols_init, state_register, state2)
                blocks2 = get_assignblock_for_state(ircfg, ir_arch, symbols_init, state_register, state1)

                dst1 = get_address(ircfg.loc_db, blocks1[0].loc_key)
                src1 = irblock.assignblks[0].instr.offset
                patches.add((src1, dst1, CNDP1))

                dst2 = get_address(ircfg.loc_db, blocks2[0].loc_key)
                src2 = src1
                patches.add((src2, dst2, CNDP0))

            elif irblock.assignblks[0].instr.name == "CMOVZ":
                state1 = None
                state2 = None

                temp_reg1 = irblock.assignblks[0].instr.args[0]
                temp_reg2 = irblock.assignblks[0].instr.args[1]

                if temp_reg1 == state_register:
                    previous_block = ircfg.get_block(ircfg.predecessors(node)[0])

                    for line in previous_block.assignblks:
                        if line.instr.name == 'MOV' and \
                                line.instr.args[0] in (temp_reg1, temp_reg2):
                            if line.instr.args[0] == state_register:
                                state1 = line.instr.args[1]
                            else:
                                state2 = line.instr.args[1]

                    if state1 and state2:
                        blocks1 = get_assignblock_for_state(ircfg, ir_arch, symbols_init, state_register, state1)
                        blocks2 = get_assignblock_for_state(ircfg, ir_arch, symbols_init, state_register, state2)

                        dst1 = get_address(ircfg.loc_db, blocks1[0].loc_key)
                        src1 = irblock.assignblks[0].instr.offset
                        patches.add((src1, dst1, CNDP1))

                        dst2 = get_address(ircfg.loc_db, blocks2[0].loc_key)
                        src2 = src1
                        patches.add((src2, dst2, CNDP0))

                    else:
                        found_state = state1 if state1 else state2
                        missing_state = state1 if not state1 else state2
                        subject_reg = temp_reg1 if not state1 else temp_reg2

                        def get_imm_write_for_reg(asmcfg, subject_reg):
                            for node in asmcfg.nodes():
                                asmblock = asmcfg.loc_key_to_block(node)
                                for line in asmblock.lines:
                                    if line.name == 'MOV' and line.args[0] == subject_reg and \
                                            isinstance(line.args[1], ExprInt):
                                        return line.args[1]
                            return None

                        missing_state = get_imm_write_for_reg(asmcfg, subject_reg)
                        if not missing_state:
                            print("[-] Something went wrong. could not find mising state!")
                            continue

                        state1 = state1 if state1 == found_state else missing_state
                        state2 = missing_state if state1 == found_state else state2

                        blocks1 = get_assignblock_for_state(ircfg, ir_arch, symbols_init, state_register, state1)
                        blocks2 = get_assignblock_for_state(ircfg, ir_arch, symbols_init, state_register, state2)

                        dst1 = get_address(ircfg.loc_db, blocks1[0].loc_key)
                        src1 = irblock.assignblks[0].instr.offset
                        patches.add((src1, dst1, CNDP1))

                        dst2 = get_address(ircfg.loc_db, blocks2[0].loc_key)
                        src2 = src1
                        patches.add((src2, dst2, CNDP0))

                else:
                    next_block = ircfg.get_block(ircfg.successors(node)[0])
                    for line in next_block.assignblks:
                        if line.instr.name == 'MOV' and line.instr.args[0] == state_register:
                            state1 = line.instr.args[1]
                            break

                    if state1:
                        blocks1 = get_assignblock_for_state(ircfg, ir_arch, symbols_init, state_register, state1)
                        src = None
                        for assignblk in next_block.assignblks:
                            if assignblk.instr.name == 'JMP':
                                src = assignblk.instr.offset

                        dst_block = ircfg.get_block(blocks1[0].loc_key)
                        if isinstance(dst_block.dst, ExprCond) and len(dst_block.assignblks):
                            if hasattr(dst_block.dst.cond, 'op') and dst_block.dst.cond.op in ('CC_S>'):
                                dst = get_address(ircfg.loc_db, dst_block.dst.src2.loc_key)
                                next_block = ircfg.get_block(dst)
                                dst = get_address(ircfg.loc_db, next_block.dst.src1.loc_key)
                            else:
                                dst = get_address(ircfg.loc_db, dst_block.dst.src1.loc_key)
                        else:
                            dst = get_address(ircfg.loc_db, blocks1[0].loc_key)

                        patches.add((src, dst, STDP))

        else:
            symbolic_engine = SymbolicExecutionEngine(ir_arch, symbols_init)
            next_addr = symbolic_engine.run_block_at(ircfg, get_address(ircfg.loc_db, node))
            next_addr = expr_simp(next_addr)

            updated_state = symbolic_engine.symbols[state_register]

            if isinstance(updated_state, ExprOp):
                updated_state = expr_simp(updated_state)

            if updated_state != symbols_init[state_register] and \
                isinstance(updated_state, ExprOp):

                irblock = ircfg.get_block(node)
                if not irblock:
                    print('[-] Could not get IRBLOCK!')
                    sys.exit()

                if len(irblock.assignblks) > 3:
                    neg_inst = False
                    for i in range(len(irblock.assignblks)):
                        if irblock.assignblks[i].instr.name == 'NEG':
                            neg_inst = True
                        if irblock.assignblks[i].instr.name == 'SBB' and \
                                irblock.assignblks[i + 1].instr.name == 'AND' and \
                                irblock.assignblks[i + 2].instr.name == 'ADD':

                            expr = symbolic_engine.symbols[state_register].copy()

                            if neg_inst:
                                state1 = expr_simp(expr.replace_expr({EAX_init: ExprInt(0, 32)}))
                                state2 = expr_simp(expr.replace_expr({EAX_init: ExprInt(1, 32)}))

                            elif irblock.assignblks[i-1].instr.name == 'CMP' and \
                                irblock.assignblks[i-2].instr.name == 'ADD' and \
                                    isinstance(irblock.assignblks[i-2].instr.args[1], ExprInt):
                                id = irblock.assignblks[i-2].instr.args[0]
                                imm = irblock.assignblks[i-2].instr.args[1]

                                state1 = expr_simp(expr.replace_expr({EAX_init: imm}).replace_expr({symbolic_engine.symbols[id].args[0]: imm}))
                                state2 = expr_simp(expr.replace_expr({EAX_init: ExprInt(-1, 32)}).replace_expr({symbolic_engine.symbols[id].args[0]: imm}))

                            blocks1 = get_assignblock_for_state(ircfg, ir_arch, symbols_init, state_register, state1)
                            blocks2 = get_assignblock_for_state(ircfg, ir_arch, symbols_init, state_register, state2)

                            process_blocks_for_patches(node, blocks1, ircfg, patches, nodes_to_walk, state1, True)
                            process_blocks_for_patches(node, blocks2, ircfg, patches, nodes_to_walk, state2, False)
                            break

            elif updated_state != symbols_init[state_register] and \
                isinstance(updated_state, ExprInt) and \
                updated_state._get_int() > 0xff:

                #print("[*] Looking for state %s" % hex(updated_state._get_int()))

                referenced_blocks = get_assignblock_for_state(ircfg, ir_arch,
                                                              symbols_init, state_register,
                                                              updated_state)
                # for block in referenced_blocks:
                #     print("\t[+] Found reference at %s" % hex(get_address(ircfg.loc_db, block.loc_key)))
                process_blocks_for_patches(node, referenced_blocks, ircfg, patches, nodes_to_walk)

            elif isinstance(next_addr, ExprCond):
                if not hasattr(next_addr.cond, 'args'):
                    if isinstance(next_addr.src1, ExprLoc):
                        dest1 = next_addr.src1.loc_key
                    else:
                        dest1 = get_loc_key_at(ircfg.loc_db, next_addr.src1._get_int())

                    if isinstance(next_addr.src2, ExprLoc):
                        dest2 = next_addr.src2.loc_key
                    else:
                        dest2 = get_loc_key_at(ircfg.loc_db, next_addr.src2._get_int())

                    if dest1 not in nodes_to_walk:
                        nodes_to_walk.append(dest1)

                    if dest2 not in nodes_to_walk:
                        nodes_to_walk.append(dest2)

                    dst2block = ircfg.get_block(dest2)
                    if dst2block.assignblks[0].instr.name == 'CMP' and \
                        dst2block.assignblks[0].instr.args[0] == state_register and \
                            len(ircfg.get_block(node).assignblks) > 1:

                        ref_block = node
                        while True:
                            irblock = ircfg.get_block(ircfg.predecessors(ref_block)[0])
                            if irblock.assignblks[0].instr.name == 'CMP' and \
                                    dst2block.assignblks[0].instr.args[0] == state_register:
                                break
                            ref_block = ircfg.predecessors(ref_block)[0]

                        asmblock = asmcfg.loc_key_to_block(node)
                        for line in asmblock.lines:
                            if line.name == 'JZ':
                                patches.add((line.offset, get_address(asmcfg.loc_db, ref_block), CNDP2))
                                true_block = ircfg.get_block(ircfg.get_block(node).dst.src2.loc_key)
                                symbolic_engine.run_block_at(ircfg, true_block.loc_key)

                                if isinstance(symbolic_engine.symbols[state_register], ExprInt):
                                    referenced_block = get_assignblock_for_state(ircfg,
                                                                                 ir_arch,
                                                                                 symbols_init,
                                                                                  state_register,
                                                                                 symbolic_engine.symbols[state_register])[0]
                                    patches.add((line.offset,
                                                 get_address(ircfg.loc_db, referenced_block.loc_key),
                                                 CNDP3))
                                break

            elif isinstance(next_addr, ExprInt):
                dest = get_loc_key_at(ircfg.loc_db, next_addr._get_int())
                if dest not in nodes_to_walk:
                    nodes_to_walk.append(get_loc_key_at(ircfg.loc_db, next_addr._get_int()))
    return list(patches)


def emotet_control_flow_unflatten(func_addr, filename):
    with open(filename, 'rb') as fstream:
        cont = Container.from_stream(fstream)

    machine = Machine(cont.arch)
    mdis = machine.dis_engine(cont.bin_stream, loc_db=cont.loc_db)
    asmcfg = mdis.dis_multiblock(func_addr)

    ir_arch = machine.ira(mdis.loc_db)
    ircfg = ir_arch.new_ircfg_from_asmcfg(asmcfg)

    state_register = get_state_register(asmcfg, get_loc_key_at(cont.loc_db, func_addr))
    if not state_register:
        print("[-] Function was not obfuscated")
        return

    to_patch_offsets = resolve_offsets(state_register, asmcfg, ircfg, ir_arch)
    to_patch_offsets.sort(key=lambda tup: tup[0])
    fix_func_cfg(filename, to_patch_offsets)

    print("[+] Function was deobfuscated!")


if __name__ == '__main__':
    filename = sys.argv[1]
    funcs = [
            0x401020,
            0x401680,
            0x401750,
            0x4019e0,
            0x401a20,
            0x401b40,
            0x4020d0,
            0x4023f0,
            0x402ec0,
            0x403030,
            0x403c90,
            0x403da0,
            0x403f00,
            0x403fd0,
            0x404170,
            0x404910,
            0x404ab0,
            0x404bc0,
            0x405490,
            0x4055c0,
            0x406520,
            0x406830,
            0x4068e0,
            0x406b00,
            0x406e60,
            0x407140,
            0x407590,
            0x4076f0,
            0x407980,
            0x407e80,
            0x408730,
            0x408990,
            0x4092a0,
            0x4087e0,
            0x407c80

            # 0x407210, To review anomalies
            # 0x404570,
            # 0x4025D0
            # 0x401dc0,
    ]

    for func in funcs:
        print("[*] Attempting to Deobfuscate Function: %s" % hex(func))
        emotet_control_flow_unflatten(func, filename)
