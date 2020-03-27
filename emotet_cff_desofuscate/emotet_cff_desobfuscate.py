from miasm.analysis.machine import Machine
from miasm.ir.symbexec import SymbolicExecutionEngine
from miasm.expression.expression import ExprCond, ExprInt, ExprOp, ExprLoc
from miasm.expression.simplifications import expr_simp
from miasm.arch.x86.regs import *
from miasm.analysis.binary import Container
import r2pipe
import sys


def get_address(loc_db, loc_key):
    return loc_db.get_location_offset(loc_key)


def get_loc_key_at(loc_db, address):
    return loc_db.get_offset_location(address)


def get_node_from_loc_key(nodes, loc_key):
    return [_node for _node in nodes if _node.loc_key == loc_key][0]


def get_state_register(asmcfg, loc_key):
    asmblock = asmcfg.loc_key_to_block(loc_key)
    for line in asmblock.lines:
        if line.name == 'MOV' and isinstance(line.args[1], ExprInt):
            return line.args[0]


def is_block_relevant(asmcfg, loc_key):
    asmblock = asmcfg.loc_key_to_block(loc_key)
    try:
        for line in asmblock.lines:
            if line.name == 'CALL':
                return True
    except:
        return False
    return False


def get_block_jz_patch_addres(asmcfg, loc_key):
    asmblock = asmcfg.loc_key_to_block(loc_key)
    for line in asmblock.lines:
        if line.name == 'NEG':
            return line.offset
    return 0


def ignore_call_results(expr_simp, expr):
    if expr.op == 'call_func_ret' or expr.op == 'call_func_stack':
        return ExprInt(0, 32)

    return expr

def get_block_last_instruction(asmcfg, loc_key):
    asmblock = asmcfg.loc_key_to_block(loc_key)
    n = len(asmblock.lines)
    last_instruction = asmblock.lines[n-2]
    return last_instruction.offset

STDP = 0
CNDP1 = 1
CNDP0 = 2

def fix_func_cfg(filename, to_patch_offsets):
    r2 = r2pipe.open(filename, ["-w"])

    to_patch_offsets.sort(key=lambda tup: tup[2])
    for n, offset in enumerate(to_patch_offsets):
        r2.cmd("s %s" % hex(offset[0]))

        if offset[2] == STDP:
            r2.cmd("wa jmp %s" % hex(offset[1]))

        elif offset[2] == CNDP1:
            r2.cmd("wa test eax, eax")
            r2.cmd("so +1")
            r2.cmd("wa jz %s" % hex(offset[1]))

        elif offset[2] == CNDP0:
            r2.cmd("so +1")
            r2.cmd("so +1")
            r2.cmd("wa jmp %s" % hex(offset[1]))

def get_assignblock_for_state(ircfg, ir_arch, symbols_init, state_register, state):
    referenced_blocks = []

    for cfgnode in ircfg.nodes():
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
                print('found referenced block at %s' % hex(get_address(ircfg.loc_db, cfgnode)))
                referenced_block = ircfg.get_block(_next_addr.src1)
                referenced_blocks.append(referenced_block)
    return referenced_blocks


def process_blocks_for_patches(node, blocks, ircfg, asmcfg, patches, nodes_to_walk, state=None, is_conditional=False):
    for block in blocks:
        if isinstance(block.dst, ExprCond) and len(block.assignblks) < 2:
            src = get_address(ircfg.loc_db, node)

            if hasattr(block.dst.cond, 'op') and block.dst.cond.op in ('CC_S>', 'CC_EQ'):
                dst = get_address(ircfg.loc_db, block.dst.src1.loc_key)
            else:
                dst = get_address(ircfg.loc_db, block.dst.src2.loc_key)

            if block.dst.src1.loc_key not in nodes_to_walk:
                nodes_to_walk.append(block.dst.src1.loc_key)

            if state and not is_conditional:
                patches.add((get_block_jz_patch_addres(asmcfg, node), dst, CNDP0))
            elif state and is_conditional:
                patches.add((get_block_jz_patch_addres(asmcfg, node), dst, CNDP1))
            else:
                patches.add((get_block_last_instruction(asmcfg, node), dst, STDP))

        else:
            src = get_address(ircfg.loc_db, node)
            dst = get_address(ircfg.loc_db, block.loc_key)

            if block.loc_key not in nodes_to_walk:
                nodes_to_walk.append(block.loc_key)

            if state and not is_conditional:
                patches.add((get_block_jz_patch_addres(asmcfg, node), dst, CNDP0))
            elif state and is_conditional:
                patches.add((get_block_jz_patch_addres(asmcfg, node), dst, CNDP1))
            elif not state and not is_conditional:
                patches.add((get_block_last_instruction(asmcfg, node), dst, STDP))

        if not state:
            print("%s -> %s" % (hex(src), hex(dst)))
        else:
            print("%s -> %s - %s" % (hex(src), hex(dst), hex(state._get_int())))


def resolve(state_register, asmcfg, ircfg, ir_arch, start_loc_key):
    patches = set()
    nodes_to_walk = list(ircfg.nodes())

    symbols_init = dict()
    for i, r in enumerate(all_regs_ids):
        symbols_init[r] = all_regs_ids_init[i]

    expr_simp.enable_passes({ExprOp: [ignore_call_results]})

    for node in nodes_to_walk:
        symbolic_engine = SymbolicExecutionEngine(ir_arch, symbols_init)
        next_addr = symbolic_engine.run_block_at(ircfg, get_address(ircfg.loc_db, node))

        if next_addr is None:
            irblock = ircfg.get_block(node)
            if not irblock:
                print('Could not get IRBLOCK')
                sys.exit()

            if len(irblock.assignblks) == 1:
                if irblock.assignblks[0].instr.name == "CMOVNZ" and irblock.assignblks[0].instr.args[0] == state_register:
                    temp_reg1 = irblock.assignblks[0].instr.args[0]
                    temp_reg2 = irblock.assignblks[0].instr.args[1]

                    state1 = None
                    state2 = None

                    print("found cmovnz conditional expression state")
                    previous_block = ircfg.get_block(ircfg.predecessors(node)[0])
                    for line in previous_block.assignblks:
                        if line.instr.name == 'MOV' and \
                                line.instr.args[0] in (temp_reg1, temp_reg2):
                            if line.instr.args[0] == state_register:
                                state1 = line.instr.args[1]
                            else:
                                state2 = line.instr.args[1]
                        if state1 and state2:
                            break

                    blocks1 = get_assignblock_for_state(ircfg, ir_arch, symbols_init, state_register, state2)
                    blocks2 = get_assignblock_for_state(ircfg, ir_arch, symbols_init, state_register, state1)

                    dst1 = get_address(ircfg.loc_db, blocks1[0].loc_key)
                    src1 = irblock.assignblks[0].instr.offset
                    patches.add((src1, dst1, CNDP1))

                    dst2 = get_address(ircfg.loc_db, blocks2[0].loc_key)
                    src2 = src1
                    patches.add((src2, dst2, CNDP0))
                    continue

                elif irblock.assignblks[0].instr.name == "CMOVZ":
                    temp_reg1 = irblock.assignblks[0].instr.args[0]
                    temp_reg2 = irblock.assignblks[0].instr.args[1]

                    state1 = None
                    state2 = None

                    if temp_reg1 == state_register:
                        print("found cmovz conditional expression double state")

                        previous_block = ircfg.get_block(ircfg.predecessors(node)[0])
                        for line in previous_block.assignblks:
                            if line.instr.name == 'MOV' and \
                                    line.instr.args[0] in (temp_reg1, temp_reg2):
                                if line.instr.args[0] == state_register:
                                    state1 = line.instr.args[1]
                                else:
                                    state2 = line.instr.args[1]

                        if state1 and state2:
                            blocks1 = get_assignblock_for_state(ircfg, ir_arch, symbols_init, state_register, state2)
                            blocks2 = get_assignblock_for_state(ircfg, ir_arch, symbols_init, state_register, state1)

                            next_block = ircfg.get_block(ircfg.successors(node)[0])

                            dst1 = get_address(ircfg.loc_db, blocks1[0].loc_key)
                            src1 = irblock.assignblks[0].instr.offset
                            patches.add((src1, dst1, CNDP1))

                            dst2 = get_address(ircfg.loc_db, blocks2[0].loc_key)
                            src2 = src1
                            patches.add((src2, dst2, CNDP0))
                            nodes_to_walk.remove(next_block.loc_key)
                            continue

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
                                print("something went wrong. could not find mising state")
                                continue

                            state1 = state1 if state1 == found_state else missing_state
                            state2 = missing_state if state1 == found_state else state2

                            blocks1 = get_assignblock_for_state(ircfg, ir_arch, symbols_init, state_register, state2)
                            blocks2 = get_assignblock_for_state(ircfg, ir_arch, symbols_init, state_register, state1)

                            dst1 = get_address(ircfg.loc_db, blocks1[0].loc_key)
                            src1 = irblock.assignblks[0].instr.offset
                            patches.add((src1, dst1, CNDP1))

                            dst2 = get_address(ircfg.loc_db, blocks2[0].loc_key)
                            src2 = src1 + 6
                            patches.add((src2, dst2, CNDP0))

                            next_block = ircfg.get_block(ircfg.successors(node)[0])
                            nodes_to_walk.remove(next_block.loc_key)
                            continue

                    else:
                        print("found cmovz conditional expression single state")
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
                            if isinstance(dst_block.dst, ExprCond) and len(dst_block.assignblks) < 2:
                                if hasattr(dst_block.dst.cond, 'op') and dst_block.dst.cond.op in ('CC_S>', 'CC_EQ'):
                                    dst = get_address(ircfg.loc_db, dst_block.dst.src1.loc_key)
                                else:
                                    dst = get_address(ircfg.loc_db, dst_block.dst.src2.loc_key)
                            else:
                                dst = get_address(ircfg.loc_db, blocks1[0].loc_key)

                            nodes_to_walk.remove(next_block.loc_key)
                            patches.add((src, dst, STDP))
                            continue

            continue


        next_addr = expr_simp(next_addr)
        #print(next_addr)

        #print(hex(get_address(ircfg.loc_db, node)))

        updated_state = symbolic_engine.symbols[state_register]
        if isinstance(updated_state, ExprOp):
            updated_state = expr_simp(updated_state)

        if updated_state != symbols_init[state_register] and \
            isinstance(updated_state, ExprOp):

            irblock = ircfg.get_block(node)
            if not irblock:
                print('Could not get IRBLOCK')
                sys.exit()

            if len(irblock.assignblks) > 4:
                for i in range(len(irblock.assignblks)):
                    if irblock.assignblks[i].instr.name == 'NEG' and \
                            irblock.assignblks[i + 1].instr.name == 'SBB' and \
                            irblock.assignblks[i + 2].instr.name == 'AND' and \
                            irblock.assignblks[i + 3].instr.name == 'ADD':

                        print("Found double state")
                        expr = symbolic_engine.symbols[state_register].copy()
                        state1 = expr_simp(expr.replace_expr({EAX_init: ExprInt(0, 32)}))
                        state2 = expr_simp(expr.replace_expr({EAX_init: ExprInt(1, 32)}))
                        blocks1 = get_assignblock_for_state(ircfg, ir_arch, symbols_init, state_register, state1)
                        blocks2 = get_assignblock_for_state(ircfg, ir_arch, symbols_init, state_register, state2)

                        process_blocks_for_patches(node, blocks1, ircfg, asmcfg,  patches, nodes_to_walk, state1, True)
                        process_blocks_for_patches(node, blocks2, ircfg, asmcfg, patches, nodes_to_walk, state2, False)

                        break

        elif updated_state != symbols_init[state_register] and \
            isinstance(updated_state, ExprInt) and \
            updated_state._get_int() > 0xff:

            print("Searching for state : %s" % hex(updated_state._get_int()))

            referenced_blocks = get_assignblock_for_state(ircfg, ir_arch, symbols_init, state_register, updated_state)
            print(hex(get_address(ircfg.loc_db, node)))
            process_blocks_for_patches(node, referenced_blocks, ircfg, asmcfg, patches, nodes_to_walk)

        elif isinstance(next_addr, ExprCond):
            if not hasattr(next_addr.cond, 'args'):
                dest1 = get_loc_key_at(ircfg.loc_db, next_addr.src1._get_int())
                dest2 = get_loc_key_at(ircfg.loc_db, next_addr.src2._get_int())

                if dest1 not in nodes_to_walk:
                    nodes_to_walk.append(dest1)

                if dest2 not in nodes_to_walk:
                    nodes_to_walk.append(dest2)

                dst2block = ircfg.get_block(get_address(ircfg.loc_db, dest2))
                if dst2block.assignblks[0].instr.name == 'CMP' and \
                    dst2block.assignblks[0].instr.args[0] == state_register and len(ircfg.get_block(node).assignblks) > 1:

                    ref_block = node
                    while True:
                        irblock = ircfg.get_block(ircfg.predecessors(ref_block)[0])
                        if irblock.assignblks[0].instr.name == 'CMP' and \
                                dst2block.assignblks[0].instr.args[0] == state_register:
                            print('Loop Detected')
                            break
                        ref_block = ircfg.predecessors(ref_block)[0]

                    asmblock = asmcfg.loc_key_to_block(node)
                    for line in asmblock.lines:
                        if line.name == 'JZ':
                            patches.add((line.offset, get_address(asmcfg.loc_db, ref_block), True))
                            break

                print('Conditional jmp')
                print('\t%s -> %s' % (hex(get_address(ircfg.loc_db, node)), hex(next_addr.src1._get_int())))
                print('\t%s -> %s' % (hex(get_address(ircfg.loc_db, node)), hex(next_addr.src2._get_int())))


        elif isinstance(next_addr, ExprInt):
            dest = get_loc_key_at(ircfg.loc_db, next_addr._get_int())
            if dest not in nodes_to_walk:
                nodes_to_walk.append(get_loc_key_at(ircfg.loc_db, next_addr._get_int()))

    return list(patches)


def main():
    filename = '/home/ulexec/Desktop/emotet.unp1.exe'
    target_addr = 0x4020D0

    with open(filename, 'rb') as fstream:
        cont = Container.from_stream(fstream)

    machine = Machine(cont.arch)
    mdis = machine.dis_engine(cont.bin_stream, loc_db=cont.loc_db)
    asmcfg = mdis.dis_multiblock(target_addr)

    ir_arch = machine.ira(mdis.loc_db)
    ircfg = ir_arch.new_ircfg_from_asmcfg(asmcfg)

    state_register = get_state_register(asmcfg, get_loc_key_at(cont.loc_db, target_addr))
    to_patch_offsets = resolve(state_register, asmcfg, ircfg, ir_arch, get_loc_key_at(cont.loc_db, target_addr))

    to_patch_offsets.sort(key=lambda tup: tup[0])
    fix_func_cfg(filename, to_patch_offsets)

if __name__ == '__main__':
    main()