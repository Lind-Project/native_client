/*
 * Copyright (c) 2012 The Native Client Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

/*
 * Hand-written Ragel machines and actions used in validator and decoding.
 *
 * Note: this file includes many different machines which are supposed to be
 * used together to implement decoding.
 *
 * E.g. modrm_parsing_ia32 implements “ModR/M style memory access” used in ia32
 * mode, but actions it uses may come from modrm_actions_ia32 or, alternatively,
 * the higher-level machine may have it's own unique implementation of actions.
 */

%%{
  machine prefix_actions;

  action branch_not_taken {
    SET_BRANCH_NOT_TAKEN(TRUE);
  }
  action branch_taken {
    SET_BRANCH_TAKEN(TRUE);
  }
  action data16_prefix {
    SET_DATA16_PREFIX(TRUE);
  }
  action lock_prefix {
    SET_LOCK_PREFIX(TRUE);
  }
  action rep_prefix {
    SET_REPZ_PREFIX(TRUE);
  }
  action repz_prefix {
    SET_REPZ_PREFIX(TRUE);
  }
  action repnz_prefix {
    SET_REPNZ_PREFIX(TRUE);
  }
  action not_data16_prefix {
    SET_DATA16_PREFIX(FALSE);
  }
  action not_lock_prefix0 {
    SET_OPERAND_NAME(0, GET_OPERAND_NAME(0) | 0x08);
    SET_LOCK_PREFIX(FALSE);
  }
  action not_lock_prefix1 {
    SET_OPERAND_NAME(1, GET_OPERAND_NAME(1) | 0x08);
    SET_LOCK_PREFIX(FALSE);
  }
  action not_repnz_prefix {
    SET_REPNZ_PREFIX(FALSE);
  }
  action not_repz_prefix {
    SET_REPZ_PREFIX(FALSE);
  }
}%%

%%{
  machine rex_actions;

  action rex_prefix {
    SET_REX_PREFIX(*current_position);
  }
}%%

%%{
  machine vex_actions_ia32;

  # VEX/XOP prefix - byte 3.
  action vex_prefix3 {
    SET_VEX_PREFIX3(*current_position);
  }
  # VEX/XOP short prefix
  action vex_prefix_short {
    /*
     * VEX.R is not used ia32 mode and VEX.W is always unset.
     *
     * Look for AMD64 version below for details of encoding.
     */
    SET_VEX_PREFIX3((*current_position) & (~VEX_W));
  }
}%%

%%{
  machine vex_actions_amd64;

  # VEX/XOP prefix - byte 2.
  action vex_prefix2 {
    SET_VEX_PREFIX2(*current_position);
  }
  # VEX/XOP prefix - byte 3.
  action vex_prefix3 {
    SET_VEX_PREFIX3(*current_position);
  }
  # VEX/XOP short prefix
  action vex_prefix_short {
    /*
     * VEX shortened prefix 2nd byte format (first byte is 0xc5):
     *     7       6       5       4       3       2       1       0
     * ┌───────┬───────┬───────┬───────┬───────┬───────┬───────┬───────┒
     * │  ¬R   │    ¬vvvv (register number)    │   L   │       pp      ┃
     * ┕━━━━━━━┷━━━━━━━┷━━━━━━━┷━━━━━━━┷━━━━━━━┷━━━━━━━┷━━━━━━━┷━━━━━━━┛
     *
     * It's converted to equivalent long (3 byte) form here (as in 0xc4):
     *     7       6       5       4       3       2       1       0
     * ┌───────┬═══════╤═══════╤═══════╤═══════╤═══════╤═══════╤═══════┒
     * │  ¬R   │ ¬X==1 │ ¬B==1 │         opcode map 1 == 00001         ┃ 2nd
     * ┕━━━━━━━┷━━━━━━━┷━━━━━━━┷━━━━━━━┷━━━━━━━┷━━━━━━━┷━━━━━━━┷━━━━━━━┛ byte
     * ┌═══════┬───────┬───────┬───────┬───────┬───────┬───────┬───────┒
     * │  W==0 │    ¬vvvv (register number)    │   L   │       pp      ┃ 3rd
     * ┕━━━━━━━┷━━━━━━━┷━━━━━━━┷━━━━━━━┷━━━━━━━┷━━━━━━━┷━━━━━━━┷━━━━━━━┛ byte
     */
    SET_VEX_PREFIX2(((*current_position) & VEX_R) | (VEX_X | VEX_B | VEX_MAP1));
    SET_VEX_PREFIX3((*current_position) & (~VEX_W));
  }
}%%

%%{
  machine modrm_actions_ia32;

  action modrm_only_base {
    SET_DISP_TYPE(DISPNONE);
    SET_MODRM_BASE(RMFromModRM(*current_position));
    SET_MODRM_INDEX(NO_REG);
    SET_MODRM_SCALE(0);
  }
  action modrm_base_disp {
    SET_MODRM_BASE(RMFromModRM(*current_position));
    SET_MODRM_INDEX(NO_REG);
    SET_MODRM_SCALE(0);
  }
  action modrm_pure_disp {
    SET_MODRM_BASE(NO_REG);
    SET_MODRM_INDEX(NO_REG);
    SET_MODRM_SCALE(0);
  }
  action modrm_pure_index {
    SET_DISP_TYPE(DISPNONE);
    SET_MODRM_BASE(NO_REG);
    SET_MODRM_INDEX(index_registers[IndexFromSIB(*current_position)]);
    SET_MODRM_SCALE(ScaleFromSIB(*current_position));
  }
  action modrm_parse_sib {
    SET_DISP_TYPE(DISPNONE);
    SET_MODRM_BASE(BaseFromSIB(*current_position));
    SET_MODRM_INDEX(index_registers[IndexFromSIB(*current_position)]);
    SET_MODRM_SCALE(ScaleFromSIB(*current_position));
  }
}%%

%%{
  machine modrm_actions_amd64;

  action modrm_only_base {
    SET_DISP_TYPE(DISPNONE);
    SET_MODRM_BASE(BaseFromSIB(*current_position) |
                   BaseExtentionFromREX(GET_REX_PREFIX()) |
                   BaseExtentionFromVEX(GET_VEX_PREFIX2()));
    SET_MODRM_INDEX(NO_REG);
    SET_MODRM_SCALE(0);
  }
  action modrm_base_disp {
    SET_MODRM_BASE(BaseFromSIB(*current_position) |
                   BaseExtentionFromREX(GET_REX_PREFIX()) |
                   BaseExtentionFromVEX(GET_VEX_PREFIX2()));
    SET_MODRM_INDEX(NO_REG);
    SET_MODRM_SCALE(0);
  }
  action modrm_rip {
    SET_MODRM_BASE(REG_RIP);
    SET_MODRM_INDEX(NO_REG);
    SET_MODRM_SCALE(0);
  }
  action modrm_pure_index {
    SET_DISP_TYPE(DISPNONE);
    SET_MODRM_BASE(NO_REG);
    SET_MODRM_INDEX(index_registers[IndexFromSIB(*current_position) |
                                    IndexExtentionFromREX(GET_REX_PREFIX()) |
                                    IndexExtentionFromVEX(GET_VEX_PREFIX2())]);
    SET_MODRM_SCALE(ScaleFromSIB(*current_position));
  }
  action modrm_parse_sib {
    SET_DISP_TYPE(DISPNONE);
    SET_MODRM_BASE(BaseFromSIB(*current_position) |
                   BaseExtentionFromREX(GET_REX_PREFIX()) |
                   BaseExtentionFromVEX(GET_VEX_PREFIX2()));
    SET_MODRM_INDEX(index_registers[IndexFromSIB(*current_position) |
                                    IndexExtentionFromREX(GET_REX_PREFIX()) |
                                    IndexExtentionFromVEX(GET_VEX_PREFIX2())]);
    SET_MODRM_SCALE(ScaleFromSIB(*current_position));
  }
}%%

%%{
  machine operand_actions_common;

  action operands_count_is_0 { SET_OPERANDS_COUNT(0); }
  action operands_count_is_1 { SET_OPERANDS_COUNT(1); }
  action operands_count_is_2 { SET_OPERANDS_COUNT(2); }
  action operands_count_is_3 { SET_OPERANDS_COUNT(3); }
  action operands_count_is_4 { SET_OPERANDS_COUNT(4); }
  action operands_count_is_5 { SET_OPERANDS_COUNT(5); }

  action operand0_16bit      { SET_OPERAND_TYPE(0, OPERAND_TYPE_16_BIT); }
  action operand0_8bit       { SET_OPERAND_TYPE(0, OPERAND_TYPE_8_BIT); }
  action operand0_32bit      { SET_OPERAND_TYPE(0, OPERAND_TYPE_32_BIT); }
  action operand0_64bit      { SET_OPERAND_TYPE(0, OPERAND_TYPE_64_BIT); }
  action operand0_128bit     { SET_OPERAND_TYPE(0, OPERAND_TYPE_128_BIT); }
  action operand0_256bit     { SET_OPERAND_TYPE(0, OPERAND_TYPE_256_BIT); }
  action operand0_creg   { SET_OPERAND_TYPE(0, OPERAND_TYPE_CONTROL_REGISTER); }
  action operand0_dreg     { SET_OPERAND_TYPE(0, OPERAND_TYPE_DEBUG_REGISTER); }
  action operand0_farptr     { SET_OPERAND_TYPE(0, OPERAND_TYPE_FAR_PTR); }
  action operand0_float32bit { SET_OPERAND_TYPE(0, OPERAND_TYPE_FLOAT_32_BIT); }
  action operand0_float64bit { SET_OPERAND_TYPE(0, OPERAND_TYPE_FLOAT_64_BIT); }
  action operand0_float80bit { SET_OPERAND_TYPE(0, OPERAND_TYPE_FLOAT_80_BIT); }
  action operand0_mmx        { SET_OPERAND_TYPE(0, OPERAND_TYPE_MMX); }
  action operand0_segreg { SET_OPERAND_TYPE(0, OPERAND_TYPE_SEGMENT_REGISTER); }
  action operand0_selector   { SET_OPERAND_TYPE(0, OPERAND_TYPE_SELECTOR); }
  action operand0_x87        { SET_OPERAND_TYPE(0, OPERAND_TYPE_ST); }
  action operand0_x87_16bit  { SET_OPERAND_TYPE(0, OPERAND_TYPE_X87_16_BIT); }
  action operand0_x87_32bit  { SET_OPERAND_TYPE(0, OPERAND_TYPE_X87_32_BIT); }
  action operand0_x87_64bit  { SET_OPERAND_TYPE(0, OPERAND_TYPE_X87_64_BIT); }
  action operand0_x87_bcd    { SET_OPERAND_TYPE(0, OPERAND_TYPE_X87_BCD); }
  action operand0_x87_env    { SET_OPERAND_TYPE(0, OPERAND_TYPE_X87_ENV); }
  action operand0_x87_mmx_xmm_state {
    SET_OPERAND_TYPE(0, OPERAND_TYPE_X87_MMX_XMM_STATE);
  }
  action operand0_x87_state  { SET_OPERAND_TYPE(0, OPERAND_TYPE_X87_STATE); }
  action operand0_xmm        { SET_OPERAND_TYPE(0, OPERAND_TYPE_XMM); }
  action operand0_ymm        { SET_OPERAND_TYPE(0, OPERAND_TYPE_YMM); }

  action operand1_8bit       { SET_OPERAND_TYPE(1, OPERAND_TYPE_8_BIT); }
  action operand1_16bit      { SET_OPERAND_TYPE(1, OPERAND_TYPE_16_BIT); }
  action operand1_32bit      { SET_OPERAND_TYPE(1, OPERAND_TYPE_32_BIT); }
  action operand1_64bit      { SET_OPERAND_TYPE(1, OPERAND_TYPE_64_BIT); }
  action operand1_128bit     { SET_OPERAND_TYPE(1, OPERAND_TYPE_128_BIT); }
  action operand1_256bit     { SET_OPERAND_TYPE(1, OPERAND_TYPE_256_BIT); }
  action operand1_creg   { SET_OPERAND_TYPE(1, OPERAND_TYPE_CONTROL_REGISTER); }
  action operand1_dreg     { SET_OPERAND_TYPE(1, OPERAND_TYPE_DEBUG_REGISTER); }
  action operand1_farptr     { SET_OPERAND_TYPE(1, OPERAND_TYPE_FAR_PTR); }
  action operand1_float32bit { SET_OPERAND_TYPE(1, OPERAND_TYPE_FLOAT_32_BIT); }
  action operand1_float64bit { SET_OPERAND_TYPE(1, OPERAND_TYPE_FLOAT_64_BIT); }
  action operand1_mmx        { SET_OPERAND_TYPE(1, OPERAND_TYPE_MMX); }
  action operand1_segreg { SET_OPERAND_TYPE(1, OPERAND_TYPE_SEGMENT_REGISTER); }
  action operand1_x87        { SET_OPERAND_TYPE(1, OPERAND_TYPE_ST); }
  action operand1_xmm        { SET_OPERAND_TYPE(1, OPERAND_TYPE_XMM); }
  action operand1_ymm        { SET_OPERAND_TYPE(1, OPERAND_TYPE_YMM); }

  action operand2_8bit       { SET_OPERAND_TYPE(2, OPERAND_TYPE_8_BIT); }
  action operand2_16bit      { SET_OPERAND_TYPE(2, OPERAND_TYPE_16_BIT); }
  action operand2_32bit      { SET_OPERAND_TYPE(2, OPERAND_TYPE_32_BIT); }
  action operand2_64bit      { SET_OPERAND_TYPE(2, OPERAND_TYPE_64_BIT); }
  action operand2_128bit     { SET_OPERAND_TYPE(2, OPERAND_TYPE_128_BIT); }
  action operand2_256bit     { SET_OPERAND_TYPE(2, OPERAND_TYPE_256_BIT); }
  action operand2_float32bit { SET_OPERAND_TYPE(2, OPERAND_TYPE_FLOAT_32_BIT); }
  action operand2_float64bit { SET_OPERAND_TYPE(2, OPERAND_TYPE_FLOAT_64_BIT); }
  action operand2_xmm        { SET_OPERAND_TYPE(2, OPERAND_TYPE_XMM); }
  action operand2_ymm        { SET_OPERAND_TYPE(2, OPERAND_TYPE_YMM); }

  action operand3_8bit       { SET_OPERAND_TYPE(3, OPERAND_TYPE_8_BIT); }
  action operand3_128bit     { SET_OPERAND_TYPE(3, OPERAND_TYPE_128_BIT); }
  action operand3_256bit     { SET_OPERAND_TYPE(3, OPERAND_TYPE_256_BIT); }
  action operand3_float32bit { SET_OPERAND_TYPE(3, OPERAND_TYPE_FLOAT_32_BIT); }
  action operand3_float64bit { SET_OPERAND_TYPE(3, OPERAND_TYPE_FLOAT_64_BIT); }
  action operand3_xmm        { SET_OPERAND_TYPE(3, OPERAND_TYPE_XMM); }
  action operand3_ymm        { SET_OPERAND_TYPE(3, OPERAND_TYPE_YMM); }

  action operand4_2bit       { SET_OPERAND_TYPE(4, OPERAND_TYPE_2_BIT); }

  action operand0_ds_rbx     { SET_OPERAND_NAME(0, REG_DS_RBX); }
  action operand0_ds_rsi     { SET_OPERAND_NAME(0, REG_DS_RSI); }
  action operand0_es_rdi     { SET_OPERAND_NAME(0, REG_ES_RDI); }
  action operand0_immediate  { SET_OPERAND_NAME(0, REG_IMM); }
  action operand0_port_dx    { SET_OPERAND_NAME(0, REG_PORT_DX); }
  action operand0_rax        { SET_OPERAND_NAME(0, REG_RAX); }
  action operand0_rcx        { SET_OPERAND_NAME(0, REG_RCX); }
  action operand0_rdx        { SET_OPERAND_NAME(0, REG_RDX); }
  action operand0_rbx        { SET_OPERAND_NAME(0, REG_RBX); }
  action operand0_rsp        { SET_OPERAND_NAME(0, REG_RSP); }
  action operand0_rbp        { SET_OPERAND_NAME(0, REG_RBP); }
  action operand0_rm         { SET_OPERAND_NAME(0, REG_RM); }
  action operand0_st         { SET_OPERAND_NAME(0, REG_ST); }

  action operand1_ds_rsi           { SET_OPERAND_NAME(1, REG_DS_RSI); }
  action operand1_es_rdi           { SET_OPERAND_NAME(1, REG_ES_RDI); }
  action operand1_immediate        { SET_OPERAND_NAME(1, REG_IMM); }
  action operand1_port_dx          { SET_OPERAND_NAME(1, REG_PORT_DX); }
  action operand1_rax              { SET_OPERAND_NAME(1, REG_RAX); }
  action operand1_rcx              { SET_OPERAND_NAME(1, REG_RCX); }
  action operand1_rm               { SET_OPERAND_NAME(1, REG_RM); }
  action operand1_second_immediate { SET_OPERAND_NAME(1, REG_IMM2); }
  action operand1_st               { SET_OPERAND_NAME(1, REG_ST); }

  action operand2_immediate        { SET_OPERAND_NAME(2, REG_IMM); }
  action operand2_rax              { SET_OPERAND_NAME(2, REG_RAX); }
  action operand2_rcx              { SET_OPERAND_NAME(2, REG_RCX); }
  action operand2_rm               { SET_OPERAND_NAME(2, REG_RM); }
  action operand2_second_immediate { SET_OPERAND_NAME(2, REG_IMM2); }

  action operand3_immediate        { SET_OPERAND_NAME(3, REG_IMM); }
  action operand3_rm               { SET_OPERAND_NAME(3, REG_RM); }
  action operand3_second_immediate { SET_OPERAND_NAME(3, REG_IMM2); }

  action operand4_immediate        { SET_OPERAND_NAME(4, REG_IMM); }

  action operand0_from_modrm_reg_norex {
    SET_OPERAND_NAME(0, RegFromModRM(*current_position));
  }
  action operand0_from_modrm_rm_norex {
    SET_OPERAND_NAME(0, RMFromModRM(*current_position));
  }
  action operand0_from_opcode_x87 {
    SET_OPERAND_NAME(0, RegFromOpcode(*current_position));
  }

  action operand1_from_modrm_reg_norex {
    SET_OPERAND_NAME(1, RegFromModRM(*current_position));
  }
  action operand1_from_modrm_rm_norex {
    SET_OPERAND_NAME(1, RMFromModRM(*current_position));
  }
  action operand1_from_opcode_x87 {
    SET_OPERAND_NAME(1, RegFromOpcode(*current_position));
  }

  action operand2_from_is4 {
    SET_OPERAND_NAME(2, RegisterFromIS4(*current_position));
  }

  action operand3_from_is4 {
    SET_OPERAND_NAME(3, RegisterFromIS4(*current_position));
  }
}%%

%%{
  machine operand_actions_ia32;

  include operand_actions_common
    "native_client/src/trusted/validator_ragel/unreviewed/parse_instruction.rl";

  action operand0_regsize {  SET_OPERAND_TYPE(0, OPERAND_TYPE_32_BIT); }
  action operand1_regsize {  SET_OPERAND_TYPE(1, OPERAND_TYPE_32_BIT); }
  action operand2_regsize {  SET_OPERAND_TYPE(2, OPERAND_TYPE_32_BIT); }

  action operand0_absolute_disp {
    SET_OPERAND_NAME(0, REG_RM);
    SET_MODRM_BASE(NO_REG);
    SET_MODRM_INDEX(NO_REG);
    SET_MODRM_SCALE(0);
  }
  action operand0_from_modrm_reg {
    SET_OPERAND_NAME(0, RegFromModRM(*current_position));
  }
  action operand0_from_modrm_rm {
    SET_OPERAND_NAME(0, RMFromModRM(*current_position));
  }
  action operand0_from_vex {
    SET_OPERAND_NAME(0, GetOperandFromVexIA32(GET_VEX_PREFIX3()));
  }
  action operand0_from_opcode {
    SET_OPERAND_NAME(0, RegFromOpcode(*current_position));
  }

  action operand1_absolute_disp {
    SET_OPERAND_NAME(1, REG_RM);
    SET_MODRM_BASE(NO_REG);
    SET_MODRM_INDEX(NO_REG);
    SET_MODRM_SCALE(0);
  }
  action operand1_from_modrm_reg {
    SET_OPERAND_NAME(1, RegFromModRM(*current_position));
  }
  action operand1_from_modrm_rm {
    SET_OPERAND_NAME(1, RMFromModRM(*current_position));
  }
  action operand1_from_vex {
    SET_OPERAND_NAME(1, GetOperandFromVexIA32(GET_VEX_PREFIX3()));
  }

  action operand2_from_modrm_reg {
    SET_OPERAND_NAME(2, RegFromModRM(*current_position));
  }
  action operand2_from_modrm_rm {
    SET_OPERAND_NAME(2, RMFromModRM(*current_position));
  }
  action operand2_from_vex {
    SET_OPERAND_NAME(2, GetOperandFromVexIA32(GET_VEX_PREFIX3()));
  }

  action operand3_from_modrm_rm {
    SET_OPERAND_NAME(3, RMFromModRM(*current_position));
  }
}%%

%%{
  machine operand_actions_amd64;

  include operand_actions_common
    "native_client/src/trusted/validator_ragel/unreviewed/parse_instruction.rl";

  action operand0_regsize {  SET_OPERAND_TYPE(0, OPERAND_TYPE_64_BIT); }
  action operand1_regsize {  SET_OPERAND_TYPE(1, OPERAND_TYPE_64_BIT); }
  action operand2_regsize {  SET_OPERAND_TYPE(2, OPERAND_TYPE_64_BIT); }

  action operand0_absolute_disp {
    SET_OPERAND_NAME(0, REG_RM);
    SET_MODRM_BASE(NO_REG);
    SET_MODRM_INDEX(REG_RIZ);
    SET_MODRM_SCALE(0);
  }
  action operand0_from_modrm_reg {
    SET_OPERAND_NAME(0, RegFromModRM(*current_position) |
                        RegisterExtentionFromREX(GET_REX_PREFIX()) |
                        RegisterExtentionFromVEX(GET_VEX_PREFIX2()));
  }
  action operand0_from_modrm_rm {
    SET_OPERAND_NAME(0, RMFromModRM(*current_position) |
                        BaseExtentionFromREX(GET_REX_PREFIX()) |
                        BaseExtentionFromVEX(GET_VEX_PREFIX2()));
  }
  action operand0_from_vex {
    SET_OPERAND_NAME(0, GetOperandFromVexAMD64(GET_VEX_PREFIX3()));
  }
  action operand0_from_opcode {
    SET_OPERAND_NAME(0, RegFromOpcode(*current_position) |
                        BaseExtentionFromREX(GET_REX_PREFIX()) |
                        BaseExtentionFromVEX(GET_VEX_PREFIX2()));
  }

  action operand1_absolute_disp {
    SET_OPERAND_NAME(1, REG_RM);
    SET_MODRM_BASE(NO_REG);
    SET_MODRM_INDEX(REG_RIZ);
    SET_MODRM_SCALE(0);
  }
  action operand1_from_modrm_reg {
    SET_OPERAND_NAME(1, RegFromModRM(*current_position) |
                        RegisterExtentionFromREX(GET_REX_PREFIX()) |
                        RegisterExtentionFromVEX(GET_VEX_PREFIX2()));
  }
  action operand1_from_modrm_rm {
    SET_OPERAND_NAME(1, RMFromModRM(*current_position) |
                        BaseExtentionFromREX(GET_REX_PREFIX()) |
                        BaseExtentionFromVEX(GET_VEX_PREFIX2()));
  }
  action operand1_from_vex {
    SET_OPERAND_NAME(1, GetOperandFromVexAMD64(GET_VEX_PREFIX3()));
  }

  action operand2_from_modrm_reg {
    SET_OPERAND_NAME(2, RegFromModRM(*current_position) |
                        RegisterExtentionFromREX(GET_REX_PREFIX()) |
                        RegisterExtentionFromVEX(GET_VEX_PREFIX2()));
  }
  action operand2_from_modrm_rm {
    SET_OPERAND_NAME(2, RMFromModRM(*current_position) |
                        BaseExtentionFromREX(GET_REX_PREFIX()) |
                        BaseExtentionFromVEX(GET_VEX_PREFIX2()));
  }
  action operand2_from_vex {
    SET_OPERAND_NAME(2, GetOperandFromVexAMD64(GET_VEX_PREFIX3()));
  }

  action operand3_from_modrm_rm {
    SET_OPERAND_NAME(3, RMFromModRM(*current_position) |
                        BaseExtentionFromREX(GET_REX_PREFIX()) |
                        BaseExtentionFromVEX(GET_VEX_PREFIX2()));
  }
}%%

%%{
  machine displacement_fields_actions;

  action disp8_operand {
    SET_DISP_TYPE(DISP8);
    SET_DISP_PTR(current_position);
  }
  action disp32_operand {
    SET_DISP_TYPE(DISP32);
    SET_DISP_PTR(current_position - 3);
  }
  action disp64_operand {
    SET_DISP_TYPE(DISP64);
    SET_DISP_PTR(current_position - 7);
  }
}%%

%%{
  machine immediate_fields_actions;

  action imm2_operand {
    SET_IMM_TYPE(IMM2);
    SET_IMM_PTR(current_position);
  }
  action imm8_operand {
    SET_IMM_TYPE(IMM8);
    SET_IMM_PTR(current_position);
  }
  action imm8_second_operand {
    SET_IMM2_TYPE(IMM8);
    SET_IMM2_PTR(current_position);
  }
  action imm16_operand {
    SET_IMM_TYPE(IMM16);
    SET_IMM_PTR(current_position - 1);
  }
  action imm16_second_operand {
    SET_IMM2_TYPE(IMM16);
    SET_IMM2_PTR(current_position - 1);
  }
  action imm32_operand {
    SET_IMM_TYPE(IMM32);
    SET_IMM_PTR(current_position - 3);
  }
  action imm32_second_operand {
    SET_IMM2_TYPE(IMM32);
    SET_IMM2_PTR(current_position - 3);
  }
  action imm64_operand {
    SET_IMM_TYPE(IMM64);
    SET_IMM_PTR(current_position - 7);
  }
  action imm64_second_operand {
    SET_IMM2_TYPE(IMM64);
    SET_IMM2_PTR(current_position - 7);
  }
}%%

%%{
  machine relative_fields_actions;

  action rel8_operand {
    SET_OPERAND_NAME(0, JMP_TO);
    SET_MODRM_BASE(REG_RIP);
    SET_MODRM_INDEX(NO_REG);
    SET_MODRM_SCALE(0);
    SET_DISP_TYPE(DISP8);
    SET_DISP_PTR(current_position);
  }
  action rel16_operand {
    SET_OPERAND_NAME(0, JMP_TO);
    SET_MODRM_BASE(REG_RIP);
    SET_MODRM_INDEX(NO_REG);
    SET_MODRM_SCALE(0);
    SET_DISP_TYPE(DISP16);
    SET_DISP_PTR(current_position - 1);
  }
  action rel32_operand {
    SET_OPERAND_NAME(0, JMP_TO);
    SET_MODRM_BASE(REG_RIP);
    SET_MODRM_INDEX(NO_REG);
    SET_MODRM_SCALE(0);
    SET_DISP_TYPE(DISP32);
    SET_DISP_PTR(current_position - 3);
  }
}%%

%%{
  machine cpuid_actions;

  action CPUFeature_3DNOW         { SET_CPU_FEATURE(CPUFeature_3DNOW);     }
  action CPUFeature_3DPRFTCH      { SET_CPU_FEATURE(CPUFeature_3DPRFTCH);  }
  action CPUFeature_AES           { SET_CPU_FEATURE(CPUFeature_AES);       }
  action CPUFeature_AESAVX        { SET_CPU_FEATURE(CPUFeature_AESAVX);    }
  action CPUFeature_ALTMOVCR8     { SET_CPU_FEATURE(CPUFeature_ALTMOVCR8); }
  action CPUFeature_AVX           { SET_CPU_FEATURE(CPUFeature_AVX);       }
  action CPUFeature_BMI1          { SET_CPU_FEATURE(CPUFeature_BMI1);      }
  action CPUFeature_CLFLUSH       { SET_CPU_FEATURE(CPUFeature_CLFLUSH);   }
  action CPUFeature_CLMUL         { SET_CPU_FEATURE(CPUFeature_CLMUL);     }
  action CPUFeature_CLMULAVX      { SET_CPU_FEATURE(CPUFeature_CLMULAVX);  }
  action CPUFeature_CMOV          { SET_CPU_FEATURE(CPUFeature_CMOV);      }
  action CPUFeature_CMOVx87       { SET_CPU_FEATURE(CPUFeature_CMOVx87);   }
  action CPUFeature_CX16          { SET_CPU_FEATURE(CPUFeature_CX16);      }
  action CPUFeature_CX8           { SET_CPU_FEATURE(CPUFeature_CX8);       }
  action CPUFeature_E3DNOW        { SET_CPU_FEATURE(CPUFeature_E3DNOW);    }
  action CPUFeature_EMMX          { SET_CPU_FEATURE(CPUFeature_EMMX);      }
  action CPUFeature_EMMXSSE       { SET_CPU_FEATURE(CPUFeature_EMMXSSE);   }
  action CPUFeature_F16C          { SET_CPU_FEATURE(CPUFeature_F16C);      }
  action CPUFeature_FMA           { SET_CPU_FEATURE(CPUFeature_FMA);       }
  action CPUFeature_FMA4          { SET_CPU_FEATURE(CPUFeature_FMA4);      }
  action CPUFeature_FXSR          { SET_CPU_FEATURE(CPUFeature_FXSR);      }
  action CPUFeature_LAHF          { SET_CPU_FEATURE(CPUFeature_LAHF);      }
  action CPUFeature_LWP           { SET_CPU_FEATURE(CPUFeature_LWP);       }
  action CPUFeature_LZCNT         { SET_CPU_FEATURE(CPUFeature_LZCNT);     }
  action CPUFeature_MMX           { SET_CPU_FEATURE(CPUFeature_MMX);       }
  action CPUFeature_MON           { SET_CPU_FEATURE(CPUFeature_MON);       }
  action CPUFeature_MOVBE         { SET_CPU_FEATURE(CPUFeature_MOVBE);     }
  action CPUFeature_MSR           { SET_CPU_FEATURE(CPUFeature_MSR);       }
  action CPUFeature_POPCNT        { SET_CPU_FEATURE(CPUFeature_POPCNT);    }
  action CPUFeature_SEP           { SET_CPU_FEATURE(CPUFeature_SEP);       }
  action CPUFeature_SFENCE        { SET_CPU_FEATURE(CPUFeature_SFENCE);    }
  action CPUFeature_SKINIT        { SET_CPU_FEATURE(CPUFeature_SKINIT);    }
  action CPUFeature_SSE           { SET_CPU_FEATURE(CPUFeature_SSE);       }
  action CPUFeature_SSE2          { SET_CPU_FEATURE(CPUFeature_SSE2);      }
  action CPUFeature_SSE3          { SET_CPU_FEATURE(CPUFeature_SSE3);      }
  action CPUFeature_SSE41         { SET_CPU_FEATURE(CPUFeature_SSE41);     }
  action CPUFeature_SSE42         { SET_CPU_FEATURE(CPUFeature_SSE42);     }
  action CPUFeature_SSE4A         { SET_CPU_FEATURE(CPUFeature_SSE4A);     }
  action CPUFeature_SSSE3         { SET_CPU_FEATURE(CPUFeature_SSSE3);     }
  action CPUFeature_SVM           { SET_CPU_FEATURE(CPUFeature_SVM);       }
  action CPUFeature_SYSCALL       { SET_CPU_FEATURE(CPUFeature_SYSCALL);   }
  action CPUFeature_TBM           { SET_CPU_FEATURE(CPUFeature_TBM);       }
  action CPUFeature_TSC           { SET_CPU_FEATURE(CPUFeature_TSC);       }
  action CPUFeature_TSCP          { SET_CPU_FEATURE(CPUFeature_TSCP);      }
  action CPUFeature_TZCNT         { SET_CPU_FEATURE(CPUFeature_TZCNT);     }
  action CPUFeature_XOP           { SET_CPU_FEATURE(CPUFeature_XOP);       }
  action CPUFeature_x87           { SET_CPU_FEATURE(CPUFeature_x87);       }
}%%

%%{
  machine att_suffix_actions;

  action att_show_name_suffix_b   { SET_ATT_INSTRUCTION_SUFFIX("b");       }
  action att_show_name_suffix_l   { SET_ATT_INSTRUCTION_SUFFIX("l");       }
  action att_show_name_suffix_ll  { SET_ATT_INSTRUCTION_SUFFIX("ll");      }
  action att_show_name_suffix_t   { SET_ATT_INSTRUCTION_SUFFIX("t");       }
  action att_show_name_suffix_s   { SET_ATT_INSTRUCTION_SUFFIX("s");       }
  action att_show_name_suffix_q   { SET_ATT_INSTRUCTION_SUFFIX("q");       }
  action att_show_name_suffix_w   { SET_ATT_INSTRUCTION_SUFFIX("w");       }
  action att_show_name_suffix_x   { SET_ATT_INSTRUCTION_SUFFIX("x");       }
  action att_show_name_suffix_y   { SET_ATT_INSTRUCTION_SUFFIX("y");       }
}%%

%%{
  machine set_spurious_prefixes;

  action set_spurious_rex_b         { SET_SPURIOUS_REX_B();                }
  action set_spurious_rex_x         { SET_SPURIOUS_REX_X();                }
  action set_spurious_rex_r         { SET_SPURIOUS_REX_R();                }
  action set_spurious_rex_w         { SET_SPURIOUS_REX_W();                }
}%%

%%{
  machine prefixes_parsing;

  data16 = 0x66 @data16_prefix;
  branch_hint = 0x2e @branch_not_taken | 0x3e @branch_taken;
  condrep = 0xf2 @repnz_prefix | 0xf3 @repz_prefix;
  lock = 0xf0 @lock_prefix;
  rep = 0xf3 @rep_prefix;
  repnz = 0xf2 @repnz_prefix;
  repz = 0xf3 @repz_prefix;
}%%

%%{
  machine prefixes_parsing_noaction;

  data16 = 0x66;
  branch_hint = 0x2e | 0x3e;
  condrep = 0xf2 | 0xf3;
  lock = 0xf0;
  rep = 0xf3;
  repnz = 0xf2;
  repz = 0xf3;
}%%

%%{
  machine rex_parsing;

  REX_NONE = 0x40 @rex_prefix;
  REX_W    = b_0100_x000 @rex_prefix;
  REX_R    = b_0100_0x00 @rex_prefix;
  REX_X    = b_0100_00x0 @rex_prefix;
  REX_B    = b_0100_000x @rex_prefix;
  REX_WR   = b_0100_xx00 @rex_prefix;
  REX_WX   = b_0100_x0x0 @rex_prefix;
  REX_WB   = b_0100_x00x @rex_prefix;
  REX_RX   = b_0100_0xx0 @rex_prefix;
  REX_RB   = b_0100_0x0x @rex_prefix;
  REX_XB   = b_0100_00xx @rex_prefix;
  REX_WRX  = b_0100_xxx0 @rex_prefix;
  REX_WRB  = b_0100_xx0x @rex_prefix;
  REX_WXB  = b_0100_x0xx @rex_prefix;
  REX_RXB  = b_0100_0xxx @rex_prefix;
  REX_WRXB = b_0100_xxxx @rex_prefix;

  rex_w    = REX_W    - REX_NONE;
  rex_r    = REX_R    - REX_NONE;
  rex_x    = REX_X    - REX_NONE;
  rex_b    = REX_B    - REX_NONE;
  rex_wr   = REX_WR   - REX_NONE;
  rex_wx   = REX_WX   - REX_NONE;
  rex_wb   = REX_WB   - REX_NONE;
  rex_rx   = REX_RX   - REX_NONE;
  rex_rb   = REX_RB   - REX_NONE;
  rex_xb   = REX_XB   - REX_NONE;
  rex_wrx  = REX_WRX  - REX_NONE;
  rex_wrb  = REX_WRB  - REX_NONE;
  rex_wxb  = REX_WXB  - REX_NONE;
  rex_rxb  = REX_RXB  - REX_NONE;
  rex_wrxb = REX_WRXB - REX_NONE;
  REXW_NONE= b_0100_1000 @rex_prefix;
  REXW_R   = b_0100_1x00 @rex_prefix;
  REXW_X   = b_0100_10x0 @rex_prefix;
  REXW_B   = b_0100_100x @rex_prefix;
  REXW_RX  = b_0100_1xx0 @rex_prefix;
  REXW_RB  = b_0100_1x0x @rex_prefix;
  REXW_XB  = b_0100_10xx @rex_prefix;
  REXW_RXB = b_0100_1xxx @rex_prefix;
}%%

%%{
  machine vex_parsing_common;

  VEX_map01 = b_xxx_00001;
  VEX_map02 = b_xxx_00010;
  VEX_map03 = b_xxx_00011;
  VEX_map08 = b_xxx_01000;
  VEX_map09 = b_xxx_01001;
  VEX_map0A = b_xxx_01010;
  VEX_map00001 = b_xxx_00001;
  VEX_map00010 = b_xxx_00010;
  VEX_map00011 = b_xxx_00011;
  VEX_map01000 = b_xxx_01000;
  VEX_map01001 = b_xxx_01001;
  VEX_map01010 = b_xxx_01010;
}%%

%%{
  machine vex_parsing_ia32;

  include vex_parsing_common
    "native_client/src/trusted/validator_ragel/unreviewed/parse_instruction.rl";
  # In ia32 mode bits R, X, and B are not used.
  VEX_NONE = b_111_xxxxx;
}%%

%%{
  machine vex_parsing_amd64;

  include vex_parsing_common
    "native_client/src/trusted/validator_ragel/unreviewed/parse_instruction.rl";
  VEX_NONE = b_111_xxxxx @vex_prefix2;
  VEX_R = b_x11_xxxxx @vex_prefix2;
  VEX_X = b_1x1_xxxxx @vex_prefix2;
  VEX_B = b_11x_xxxxx @vex_prefix2;
  VEX_RX = b_xx1_xxxxx @vex_prefix2;
  VEX_RB = b_x1x_xxxxx @vex_prefix2;
  VEX_XB = b_1xx_xxxxx @vex_prefix2;
  VEX_RXB = b_xxx_xxxxx @vex_prefix2;
}%%

%%{
  machine modrm_parsing_common;

  operand_sib_base_index =
    (b_00_xxx_100 . (any - b_xx_xxx_101) @modrm_parse_sib) |
    (b_01_xxx_100 . any @modrm_parse_sib . disp8) |
    (b_10_xxx_100 . any @modrm_parse_sib . disp32);
  operand_sib_pure_index =
    b_00_xxx_100 . b_xx_xxx_101 @modrm_pure_index . disp32;
  operand_disp  =
    ((b_01_xxx_xxx - b_xx_xxx_100) @modrm_base_disp . disp8) |
    ((b_10_xxx_xxx - b_xx_xxx_100) @modrm_base_disp . disp32);
  single_register_memory =
    (b_00_xxx_xxx - b_xx_xxx_100 - b_xx_xxx_101) @modrm_only_base;
  modrm_memory =
    operand_disp | operand_rip |
    operand_sib_base_index | operand_sib_pure_index |
    single_register_memory;
  modrm_registers = b_11_xxx_xxx;

  # Operations selected using opcode in ModR/M.
  opcode_0 = b_xx_000_xxx;
  opcode_1 = b_xx_001_xxx;
  opcode_2 = b_xx_010_xxx;
  opcode_3 = b_xx_011_xxx;
  opcode_4 = b_xx_100_xxx;
  opcode_5 = b_xx_101_xxx;
  opcode_6 = b_xx_110_xxx;
  opcode_7 = b_xx_111_xxx;
  # Used for segment operations: there only 6 segment registers.
  opcode_s = (any - b_xx_110_xxx - b_xx_111_xxx);
  # This is used to move operand name detection after first byte of ModRM.
  opcode_m = (any - b_11_xxx_xxx);
  opcode_r = b_11_xxx_xxx;
}%%

%%{
  machine modrm_parsing_ia32;

  # It's pure disp32 in IA32 case, but offset(%rip) in x86-64 case.
  operand_rip = b_00_xxx_101 @modrm_pure_disp . disp32;
  include modrm_parsing_common
    "native_client/src/trusted/validator_ragel/unreviewed/parse_instruction.rl";
}%%

%%{
  machine modrm_parsing_amd64;

  # It's pure disp32 in IA32 case, but offset(%rip) in x86-64 case.
  operand_rip = b_00_xxx_101 @modrm_rip . disp32;
  include modrm_parsing_common
    "native_client/src/trusted/validator_ragel/unreviewed/parse_instruction.rl";
}%%

%%{
  machine modrm_parsing_common_noactions;

  operand_sib_base_index =
    (b_00_xxx_100 . (any - b_xx_xxx_101)) |
    (b_01_xxx_100 . any . disp8) |
    (b_10_xxx_100 . any . disp32);
  operand_sib_pure_index =
    b_00_xxx_100 . b_xx_xxx_101 . disp32;
  operand_disp  =
    ((b_01_xxx_xxx - b_xx_xxx_100) . disp8) |
    ((b_10_xxx_xxx - b_xx_xxx_100) . disp32);
  single_register_memory =
    (b_00_xxx_xxx - b_xx_xxx_100 - b_xx_xxx_101);
  modrm_memory =
    operand_disp | operand_rip |
    operand_sib_base_index | operand_sib_pure_index |
    single_register_memory;
  modrm_registers = b_11_xxx_xxx;

  # Operations selected using opcode in ModR/M.
  opcode_0 = b_xx_000_xxx;
  opcode_1 = b_xx_001_xxx;
  opcode_2 = b_xx_010_xxx;
  opcode_3 = b_xx_011_xxx;
  opcode_4 = b_xx_100_xxx;
  opcode_5 = b_xx_101_xxx;
  opcode_6 = b_xx_110_xxx;
  opcode_7 = b_xx_111_xxx;
  # Used for segment operations: there only 6 segment registers.
  opcode_s = (any - b_xx_110_xxx - b_xx_111_xxx);
  # This is used to move operand name detection after first byte of ModRM.
  opcode_m = (any - b_11_xxx_xxx);
  opcode_r = b_11_xxx_xxx;
}%%

%%{
  machine modrm_parsing_ia32_noactions;

  # It's pure disp32 in IA32 case, but offset(%rip) in x86-64 case.
  operand_rip = b_00_xxx_101 . disp32;
  include modrm_parsing_common_noactions
    "native_client/src/trusted/validator_ragel/unreviewed/parse_instruction.rl";
}%%

%%{
  machine modrm_parsing_amd64_noactions;

  # It's pure disp32 in IA32 case, but offset(%rip) in x86-64 case.
  operand_rip = b_00_xxx_101 . disp32;
  include modrm_parsing_common_noactions
    "native_client/src/trusted/validator_ragel/unreviewed/parse_instruction.rl";
}%%

%%{
  machine relative_fields_parsing;

  rel8  = any @rel8_operand;
  rel16 = any{2} @rel16_operand;
  rel32 = any{4} @rel32_operand;
}%%

%%{
  machine displacement_fields_parsing;

  disp8  = any @disp8_operand;
  disp32 = any{4} @disp32_operand;
  disp64 = any{8} @disp64_operand;
}%%

%%{
  machine immediate_fields_parsing_common;

  imm8 = any @imm8_operand;
  imm16 = any{2} @imm16_operand;
  imm32 = any{4} @imm32_operand;
  imm64 = any{8} @imm64_operand;
  imm8n2 = any @imm8_second_operand;
  imm16n2 = any{2} @imm16_second_operand;
}%%

%%{
  machine immediate_fields_parsing_ia32;

  include immediate_fields_parsing_common
    "native_client/src/trusted/validator_ragel/unreviewed/parse_instruction.rl";
  imm2 = b_0xxx_00xx @imm2_operand;
}%%

%%{
  machine immediate_fields_parsing_amd64;

  include immediate_fields_parsing_common
    "native_client/src/trusted/validator_ragel/unreviewed/parse_instruction.rl";
  imm2 = b_xxxx_00xx @imm2_operand;
}%%

%%{
  machine displacement_fields_mark;

  action disp8_operand_begin { }
  action disp8_operand_end { }
  action disp32_operand_begin { }
  action disp32_operand_end { }
  action disp64_operand_begin { }
  action disp64_operand_end { }

  disp8  = any >disp8_operand_begin @disp8_operand_end;
  disp32 = any{3} $disp32_operand_begin any @disp32_operand_end;
  disp64 = any{7} $disp64_operand_begin any @disp64_operand_end;
}%%

%%{
  machine immediate_fields_mark_common;

  action imm8_operand_begin { }
  action imm8_operand_end { }
  action imm16_operand_begin { }
  action imm16_operand_end { }
  action imm32_operand_begin { }
  action imm32_operand_end { }
  action imm64_operand_begin { }
  action imm64_operand_end { }

  imm8 = any >imm8_operand_begin @imm8_operand_end;
  imm16 = any $imm16_operand_begin any @imm16_operand_end;
  imm32 = any{3} $imm32_operand_begin any @imm32_operand_end;
  imm64 = any{7} $imm64_operand_begin any @imm64_operand_end;
  imm8n2 = any >imm8_operand_begin @imm8_operand_end;
  imm16n2 = any $imm16_operand_begin any @imm16_operand_end;
}%%

%%{
  machine immediate_fields_mark_ia32;

  include immediate_fields_mark_common
    "native_client/src/trusted/validator_ragel/unreviewed/parse_instruction.rl";
  imm2 = b_0xxx_00xx;
}%%

%%{
  machine immediate_fields_mark_amd64;

  include immediate_fields_mark_common
    "native_client/src/trusted/validator_ragel/unreviewed/parse_instruction.rl";
  imm2 = b_xxxx_00xx;
}%%

%%{
  machine relative_fields_mark;

  action rel8_operand_begin { }
  action rel8_operand_end { }
  action rel16_operand_begin { }
  action rel16_operand_end { }
  action rel32_operand_begin { }
  action rel32_operand_end { }

  rel8  = any >rel8_operand_begin @rel8_operand_end;
  rel16 = any $rel16_operand_begin any @rel16_operand_end;
  rel32 = any{3} $rel32_operand_begin any @rel32_operand_end;
}%%


%%{
  machine decoder;

  action end_of_instruction_cleanup {
    process_instruction(instruction_start, current_position+1, &instruction,
                        userdata);
    instruction_start = current_position + 1;
    SET_DISP_TYPE(DISPNONE);
    SET_IMM_TYPE(IMMNONE);
    SET_IMM2_TYPE(IMMNONE);
    SET_REX_PREFIX(FALSE);
    SET_DATA16_PREFIX(FALSE);
    SET_LOCK_PREFIX(FALSE);
    SET_REPNZ_PREFIX(FALSE);
    SET_REPZ_PREFIX(FALSE);
    SET_BRANCH_NOT_TAKEN(FALSE);
    SET_BRANCH_TAKEN(FALSE);
    /* Top three bis of VEX2 are inverted: see AMD/Intel manual.  */
    SET_VEX_PREFIX2(VEX_R | VEX_X | VEX_B);
    SET_VEX_PREFIX3(0x00);
    SET_ATT_INSTRUCTION_SUFFIX(NULL);
    CLEAR_SPURIOUS_REX_B();
    CLEAR_SPURIOUS_REX_X();
    CLEAR_SPURIOUS_REX_R();
    CLEAR_SPURIOUS_REX_W();
  }

  action report_fatal_error {
    process_error(current_position, userdata);
    result = FALSE;
    goto error_detected;
  }

  decoder = (one_instruction @end_of_instruction_cleanup)*
    $!report_fatal_error;
}%%
