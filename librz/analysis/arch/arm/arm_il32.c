// SPDX-FileCopyrightText: 2022 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>
#include <capstone.h>

#include "arm_cs.h"
#include "arm_accessors.h"

#include <rz_il/rz_il_opbuilder_begin.h>

/**
 * Variable name for a register given by cs
 */
static const char *reg_var_name(arm_reg reg) {
	const char *names[] = {
		// TODO: check how well-packed this is any maybe use switch instead
		[ARM_REG_LR] = "lr",
		[ARM_REG_SP] = "sp",
		[ARM_REG_Q0] = "q0",
		[ARM_REG_Q1] = "q1",
		[ARM_REG_Q2] = "q2",
		[ARM_REG_Q3] = "q3",
		[ARM_REG_Q4] = "q4",
		[ARM_REG_Q5] = "q5",
		[ARM_REG_Q6] = "q6",
		[ARM_REG_Q7] = "q7",
		[ARM_REG_Q8] = "q8",
		[ARM_REG_Q9] = "q9",
		[ARM_REG_Q10] = "q10",
		[ARM_REG_Q11] = "q11",
		[ARM_REG_Q12] = "q12",
		[ARM_REG_Q13] = "q13",
		[ARM_REG_Q14] = "q14",
		[ARM_REG_Q15] = "q15",
		[ARM_REG_R0] = "r0",
		[ARM_REG_R1] = "r1",
		[ARM_REG_R2] = "r2",
		[ARM_REG_R3] = "r3",
		[ARM_REG_R4] = "r4",
		[ARM_REG_R5] = "r5",
		[ARM_REG_R6] = "r6",
		[ARM_REG_R7] = "r7",
		[ARM_REG_R8] = "r8",
		[ARM_REG_R9] = "r9",
		[ARM_REG_R10] = "r10",
		[ARM_REG_R11] = "r11",
		[ARM_REG_R12] = "r12"
	};
	if (reg < 0 || reg >= RZ_ARRAY_SIZE(names)) {
		return NULL;
	}
	return names[reg];
}

/**
 * IL to read the given reg
 */
static RzILOpBitVector *read_reg(cs_insn *insn, arm_reg reg) {
	const char *var = reg_var_name(reg);
	return var ? VARG(var) : NULL;
}

/**
 * IL for arm condition
 * unconditional is returned as NULL (rather than true), for simpler code
 */
static RZ_NULLABLE RzILOpBool *cond(arm_cc c) {
	switch (c) {
	case ARM_CC_EQ:
		return VARG("zf");
	case ARM_CC_NE:
		return INV(VARG("zf"));
	case ARM_CC_HS:
		return VARG("cf");
	case ARM_CC_LO:
		return INV(VARG("cf"));
	case ARM_CC_MI:
		return VARG("nf");
	case ARM_CC_PL:
		return INV(VARG("nf"));
	case ARM_CC_VS:
		return VARG("vf");
	case ARM_CC_VC:
		return INV(VARG("vf"));
	case ARM_CC_HI:
		return AND(VARG("cf"), INV(VARG("zf")));
	case ARM_CC_LS:
		return AND(INV(VARG("cf")), VARG("zf"));
	case ARM_CC_GE:
		return INV(XOR(VARG("nf"), VARG("vf")));
	case ARM_CC_LT:
		return XOR(VARG("nf"), VARG("vf"));
	case ARM_CC_GT:
		return AND(INV(VARG("zf")), INV(XOR(VARG("nf"), VARG("vf"))));
	case ARM_CC_LE:
		return AND(VARG("zf"), XOR(VARG("nf"), VARG("vf")));
	case ARM_CC_AL:
	default:
		return NULL;
	}
}

/**
 * IL to retrieve the value of the \p n -th arg of \p insn
 */
static RzILOpBitVector *arg(csh *handle, cs_insn *insn, int n) {
	RzILOpBitVector *r;
	switch (insn->detail->arm.operands[n].type) {
	case ARM_OP_REG:
		r = read_reg(insn, insn->detail->arm.operands[n].reg);
#if 0
		if (ISSHIFTED(n)) {
			sprintf(buf, "%u,%s,%s",
				LSHIFT2(n),
				rz_str_get_null(cs_reg_name(*handle,
					insn->detail->arm.operands[n].reg)),
				DECODE_SHIFT(n));
		} else {
#endif
		return r;
	case ARM_OP_IMM:
		return U32((ut32)insn->detail->arm.operands[n].imm);
		break;
	default:
		break;
	}
	return NULL;
}

#define ARG(x) arg(handle, insn, x)

static RzILOpEffect *il_unconditional(csh *handle, cs_insn *insn, bool thumb) {
	switch (insn->id) {
	case ARM_INS_B: {
		RzILOpBitVector *dst = ARG(0);
		return dst ? JMP(dst) : NULL;
	}
	default:
		return NULL;
	}
}

RZ_IPI RzILOpEffect *rz_arm_cs_32_il(csh *handle, cs_insn *insn, bool thumb) {
	RzILOpEffect *eff = il_unconditional(handle, insn, thumb);
	if (!eff) {
		return NULL;
	}
	RzILOpBool *c = cond(insn->detail->arm.cc);
	if (c) {
		return BRANCH(c, eff, NOP);
	}
	return eff;
}

#include <rz_il/rz_il_opbuilder_end.h>

RZ_IPI RzAnalysisILConfig *rz_arm_cs_32_il_config(bool big_endian) {
	return rz_analysis_il_config_new(32, big_endian, 32);
}
