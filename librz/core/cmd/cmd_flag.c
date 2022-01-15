// SPDX-FileCopyrightText: 2009-2021 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stddef.h>
#include "rz_cons.h"
#include "rz_core.h"

static const char *help_msg_f[] = {
	"Usage: f", "[?] [flagname]", " # Manage offset-name flags",
	"f", "", "list flags (will only list flags from selected flagspaces)",
	"f?", "flagname", "check if flag exists or not, See ?? and ?!",
	"f.", " [*[*]]", "list local per-function flags (*) as rizin commands",
	"f.", "blah=$$+12", "set local function label named 'blah'",
	"f.", " fname", "list all local labels for the given function",
	"f,", "", "table output for flags",
	"f*", "", "list flags in r commands",
	"f", " name 12 @ 33", "set flag 'name' with length 12 at offset 33",
	"f", " name = 33", "alias for 'f name @ 33' or 'f name 1 33'",
	"f", " name 12 33 [cmt]", "same as above + optional comment",
	"f-", ".blah@fcn.foo", "delete local label from function at current seek (also f.-)",
	"f--", "", "delete all flags and flagspaces (deinit)",
	"f+", "name 12 @ 33", "like above but creates new one if doesnt exist",
	"f-", "name", "remove flag 'name'",
	"f-", "@addr", "remove flag at address expression",
	"f=", " [glob]", "list range bars graphics with flag offsets and sizes",
	"fa", " [name] [alias]", "alias a flag to evaluate an expression",
	"fb", " [addr]", "set base address for new flags",
	"fb", " [addr] [flag*]", "move flags matching 'flag' to relative addr",
	"fc", "[?][name] [color]", "set color for given flag",
	"fC", " [name] [cmt]", "set comment for given flag",
	"ff", " ([glob])", "distance in bytes to reach the next flag (see sn/sp)",
	"fi", " [size] | [from] [to]", "show flags in current block or range",
	"fg", "[*] ([prefix])", "construct a graph with the flag names",
	"fj", "", "list flags in JSON format",
	"fl", " (@[flag]) [size]", "show or set flag length (size)",
	"fla", " [glob]", "automatically compute the size of all flags matching glob",
	"fm", " addr", "move flag at current offset to new address",
	"fn", "", "list flags displaying the real name (demangled)",
	"fnj", "", "list flags displaying the real name (demangled) in JSON format",
	"fN", "", "show real name of flag at current address",
	"fN", " [[name]] [realname]", "set flag real name (if no flag name current seek one is used)",
	"fO", " [glob]", "flag as ordinals (sym.* func.* method.*)",
	//" fc [name] [cmt]  ; set execution command for a specific flag"
	"fr", " [[old]] [new]", "rename flag (if no new flag current seek one is used)",
	"fR", "[?] [f] [t] [m]", "relocate all flags matching f&~m 'f'rom, 't'o, 'm'ask",
	"fV", "[*-] [nkey] [offset]", "dump/restore visual marks (mK/'K)",
	"fx", "[d]", "show hexdump (or disasm) of flag:flagsize",
	"fq", "", "list flags in quiet mode",
	NULL
};

static bool listFlag(RzFlagItem *flag, void *user) {
	rz_list_append(user, flag);
	return true;
}

static size_t countMatching(const char *a, const char *b) {
	size_t matches = 0;
	for (; *a && *b; a++, b++) {
		if (*a != *b) {
			break;
		}
		matches++;
	}
	return matches;
}

static const char *__isOnlySon(RzCore *core, RzList *flags, const char *kw) {
	RzListIter *iter;
	RzFlagItem *f;

	size_t count = 0;
	char *fname = NULL;
	rz_list_foreach (flags, iter, f) {
		if (!strncmp(f->name, kw, strlen(kw))) {
			count++;
			if (count > 1) {
				return NULL;
			}
			fname = f->name;
		}
	}
	return fname;
}

static RzList *__childrenFlagsOf(RzCore *core, RzList *flags, const char *prefix) {
	RzList *list = rz_list_newf(free);
	RzListIter *iter, *iter2;
	RzFlagItem *f, *f2;
	char *fn;

	const size_t prefix_len = strlen(prefix);
	rz_list_foreach (flags, iter, f) {
		if (prefix_len > 0 && strncmp(f->name, prefix, prefix_len)) {
			continue;
		}
		if (prefix_len > strlen(f->name)) {
			continue;
		}
		if (rz_cons_is_breaked()) {
			break;
		}
		const char *name = f->name;
		int name_len = strlen(name);
		rz_list_foreach (flags, iter2, f2) {
			if (prefix_len > strlen(f2->name)) {
				continue;
			}
			if (prefix_len > 0 && strncmp(f2->name, prefix, prefix_len)) {
				continue;
			}
			int matching = countMatching(name, f2->name);
			if (matching < prefix_len || matching == name_len) {
				continue;
			}
			if (matching > name_len) {
				break;
			}
			if (matching < name_len) {
				name_len = matching;
			}
		}
		char *kw = rz_str_ndup(name, name_len + 1);
		const int kw_len = strlen(kw);
		const char *only = __isOnlySon(core, flags, kw);
		if (only) {
			free(kw);
			kw = strdup(only);
		} else {
			const char *fname = NULL;
			size_t fname_len = 0;
			rz_list_foreach (flags, iter2, f2) {
				if (strncmp(f2->name, kw, kw_len)) {
					continue;
				}
				if (fname) {
					int matching = countMatching(fname, f2->name);
					if (fname_len) {
						if (matching < fname_len) {
							fname_len = matching;
						}
					} else {
						fname_len = matching;
					}
				} else {
					fname = f2->name;
				}
			}
			if (fname_len > 0) {
				free(kw);
				kw = rz_str_ndup(fname, fname_len);
			}
		}

		bool found = false;
		rz_list_foreach (list, iter2, fn) {
			if (!strcmp(fn, kw)) {
				found = true;
				break;
			}
		}
		if (found) {
			free(kw);
		} else {
			if (strcmp(prefix, kw)) {
				rz_list_append(list, kw);
			} else {
				free(kw);
			}
		}
	}
	return list;
}

static void __printRecursive(RzCore *core, RzList *list, const char *prefix, int mode, int depth);

static void __printRecursive(RzCore *core, RzList *flags, const char *prefix, int mode, int depth) {
	char *fn;
	RzListIter *iter;
	const int prefix_len = strlen(prefix);
	// eprintf ("# fg %s\n", prefix);
	if (mode == '*' && !*prefix) {
		rz_cons_printf("agn root\n");
	}
	if (rz_flag_get(core->flags, prefix)) {
		return;
	}
	RzList *children = __childrenFlagsOf(core, flags, prefix);
	rz_list_foreach (children, iter, fn) {
		if (!strcmp(fn, prefix)) {
			continue;
		}
		if (mode == '*') {
			rz_cons_printf("agn %s %s\n", fn, fn + prefix_len);
			rz_cons_printf("age %s %s\n", *prefix ? prefix : "root", fn);
		} else {
			rz_cons_printf("%s %s\n", rz_str_pad(' ', prefix_len), fn + prefix_len);
		}
		// rz_cons_printf (".fg %s\n", fn);
		__printRecursive(core, flags, fn, mode, depth + 1);
	}
	rz_list_free(children);
}

static void __flag_graph(RzCore *core, const char *input, int mode) {
	RzList *flags = rz_list_newf(NULL);
	rz_flag_foreach_space(core->flags, rz_flag_space_cur(core->flags), listFlag, flags);
	__printRecursive(core, flags, input, mode, 0);
	rz_list_free(flags);
}

static int cmpflag(const void *_a, const void *_b) {
	const RzFlagItem *flag1 = _a, *flag2 = _b;
	return (flag1->offset - flag2->offset);
}

RZ_IPI void rz_core_flag_describe(RzCore *core, ut64 addr, bool strict_offset, RzCmdStateOutput *state) {
	RzFlagItem *f = rz_flag_get_at(core->flags, addr, !strict_offset);
	if (!f) {
		return;
	}
	PJ *pj = state->d.pj;
	switch (state->mode) {
	case RZ_OUTPUT_MODE_JSON:
		pj_o(pj);
		pj_kn(pj, "offset", f->offset);
		pj_ks(pj, "name", f->name);
		// Print flag's real name if defined
		if (f->realname) {
			pj_ks(pj, "realname", f->realname);
		}
		pj_end(pj);
		break;
	case RZ_OUTPUT_MODE_STANDARD: {
		// Print realname if exists and asm.flags.real is enabled
		const char *name = core->flags->realnames && f->realname ? f->realname : f->name;
		if (f->offset != addr) {
			rz_cons_printf("%s + %d\n", name, (int)(addr - f->offset));
		} else {
			rz_cons_println(name);
		}
		break;
	}
	default:
		rz_warn_if_reached();
		break;
	}
}

RZ_IPI RzCmdStatus rz_flag_describe_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	rz_core_flag_describe(core, core->offset, false, state);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_flag_describe_at_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	const RzList *flags = rz_flag_get_list(core->flags, core->offset);
	if (!flags) {
		return RZ_CMD_STATUS_OK;
	}
	PJ *pj = state->d.pj;
	rz_cmd_state_output_array_start(state);
	RzFlagItem *flag;
	RzListIter *iter;
	// Sometimes an address has multiple flags assigned to, show them all
	rz_list_foreach (flags, iter, flag) {
		if (!flag) {
			continue;
		}
		switch (state->mode) {
		case RZ_OUTPUT_MODE_JSON:
			pj_o(pj);
			pj_ks(pj, "name", flag->name);
			if (flag->realname) {
				pj_ks(pj, "realname", flag->realname);
			}
			pj_end(pj);
			break;
		case RZ_OUTPUT_MODE_STANDARD:
			// Print realname if exists and asm.flags.real is enabled
			if (core->flags->realnames && flag->realname) {
				rz_cons_println(flag->realname);
			} else {
				rz_cons_println(flag->name);
			}
			break;
		default:
			rz_warn_if_reached();
			break;
		}
	}
	rz_cmd_state_output_array_end(state);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_flag_describe_closest_handler(RzCore *core, int argc, const char **argv) {
	RzList *temp = rz_flag_all_list(core->flags, true);
	if (!temp) {
		return RZ_CMD_STATUS_OK;
	}
	ut64 loff = 0;
	ut64 uoff = 0;
	ut64 curseek = core->offset;
	char *lmatch = NULL, *umatch = NULL;
	RzFlagItem *flag;
	RzListIter *iter;
	rz_list_sort(temp, &cmpflag);
	rz_list_foreach (temp, iter, flag) {
		if (strstr(flag->name, argv[1]) != NULL) {
			if (flag->offset < core->offset) {
				loff = flag->offset;
				lmatch = flag->name;
				continue;
			}
			uoff = flag->offset;
			umatch = flag->name;
			break;
		}
	}
	char *match = (curseek - loff) < (uoff - curseek) ? lmatch : umatch;
	if (match) {
		if (*match) {
			rz_cons_println(match);
		}
	}
	rz_list_free(temp);
	return RZ_CMD_STATUS_OK;
}

static void flag_zone_list(RzFlag *f, RzCmdStateOutput *state) {
	if (!f->zones) {
		return;
	}
	RzListIter *iter;
	RzFlagZoneItem *zi;
	PJ *pj = state->d.pj;
	rz_cmd_state_output_array_start(state);
	rz_list_foreach (f->zones, iter, zi) {
		switch (state->mode) {
		case RZ_OUTPUT_MODE_JSON:
			pj_o(pj);
			pj_ks(pj, "name", zi->name);
			pj_ki(pj, "from", zi->from);
			pj_ki(pj, "to", zi->to);
			pj_end(pj);
			break;
		case RZ_OUTPUT_MODE_STANDARD:
			rz_cons_printf("0x08%" PFMT64x "  0x%08" PFMT64x "  %s\n",
				zi->from, zi->to, zi->name);
			break;
		default:
			rz_warn_if_reached();
			break;
		}
	}
	rz_cmd_state_output_array_end(state);
}

RZ_IPI RzCmdStatus rz_flag_zone_add_handler(RzCore *core, int argc, const char **argv) {
	rz_flag_zone_add(core->flags, argv[1], core->offset);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_flag_zone_remove_handler(RzCore *core, int argc, const char **argv) {
	rz_flag_zone_del(core->flags, argv[1]);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_flag_zone_remove_all_handler(RzCore *core, int argc, const char **argv) {
	rz_flag_zone_reset(core->flags);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_flag_zone_around_handler(RzCore *core, int argc, const char **argv) {
	const char *a = NULL, *b = NULL;
	rz_flag_zone_around(core->flags, core->offset, &a, &b);
	rz_cons_printf("%s %s\n", a ? a : "~", b ? b : "~");
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_flag_zone_list_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	flag_zone_list(core->flags, state);
	return RZ_CMD_STATUS_OK;
}

struct flagbar_t {
	RzCore *core;
	int cols;
};

static bool flagbar_foreach(RzFlagItem *fi, void *user) {
	struct flagbar_t *u = (struct flagbar_t *)user;
	ut64 min = 0, max = rz_io_size(u->core->io);
	RzIOMap *m = rz_io_map_get(u->core->io, fi->offset);
	if (m) {
		min = m->itv.addr;
		max = m->itv.addr + m->itv.size;
	}
	rz_cons_printf("0x%08" PFMT64x " ", fi->offset);
	rz_print_rangebar(u->core->print, fi->offset, fi->offset + fi->size, min, max, u->cols);
	rz_cons_printf("  %s\n", fi->name);
	return true;
}

static void flagbars(RzCore *core, const char *glob) {
	int cols = rz_cons_get_size(NULL);
	cols -= 80;
	if (cols < 0) {
		cols += 80;
	}

	struct flagbar_t u = { .core = core, .cols = cols };
	rz_flag_foreach_space_glob(core->flags, glob, rz_flag_space_cur(core->flags), flagbar_foreach, &u);
}

struct flag_to_flag_t {
	ut64 next;
	ut64 offset;
};

static bool flag_to_flag_foreach(RzFlagItem *fi, void *user) {
	struct flag_to_flag_t *u = (struct flag_to_flag_t *)user;
	if (fi->offset < u->next && fi->offset > u->offset) {
		u->next = fi->offset;
	}
	return true;
}

static int flag_to_flag(RzCore *core, const char *glob) {
	rz_return_val_if_fail(glob, 0);
	glob = rz_str_trim_head_ro(glob);
	struct flag_to_flag_t u = { .next = UT64_MAX, .offset = core->offset };
	rz_flag_foreach_glob(core->flags, glob, flag_to_flag_foreach, &u);
	if (u.next != UT64_MAX && u.next > core->offset) {
		return u.next - core->offset;
	}
	return 0;
}

typedef struct {
	RzTable *t;
} FlagTableData;

static bool __tableItemCallback(RzFlagItem *flag, void *user) {
	FlagTableData *ftd = user;
	if (!RZ_STR_ISEMPTY(flag->name)) {
		RzTable *t = ftd->t;
		const char *spaceName = (flag->space && flag->space->name) ? flag->space->name : "";
		const char *addr = sdb_fmt("0x%08" PFMT64x, flag->offset);
		rz_table_add_row(t, addr, sdb_fmt("%" PFMT64d, flag->size), spaceName, flag->name, NULL);
	}
	return true;
}

static void cmd_flag_table(RzCore *core, const char *input) {
	const char fmt = *input++;
	const char *q = input;
	FlagTableData ftd = { 0 };
	RzTable *t = rz_core_table(core);
	ftd.t = t;
	RzTableColumnType *typeString = rz_table_type("string");
	RzTableColumnType *typeNumber = rz_table_type("number");
	rz_table_add_column(t, typeNumber, "addr", 0);
	rz_table_add_column(t, typeNumber, "size", 0);
	rz_table_add_column(t, typeString, "space", 0);
	rz_table_add_column(t, typeString, "name", 0);

	RzSpace *curSpace = rz_flag_space_cur(core->flags);
	rz_flag_foreach_space(core->flags, curSpace, __tableItemCallback, &ftd);
	if (rz_table_query(t, q)) {
		char *s = (fmt == 'j')
			? rz_table_tojson(t)
			: rz_table_tostring(t);
		rz_cons_printf("%s\n", s);
		free(s);
	}
	rz_table_free(t);
}

RZ_IPI RzCmdStatus rz_flag_tag_add_handler(RzCore *core, int argc, const char **argv) {
	rz_flag_tags_set(core->flags, argv[1], argv[2]);
	return RZ_CMD_STATUS_OK;
}

static void flag_tag_print(RzCore *core, const char *tag, RzCmdStateOutput *state) {
	PJ *pj = state->d.pj;
	switch (state->mode) {
	case RZ_OUTPUT_MODE_JSON: {
		pj_k(pj, tag);
		pj_a(pj);
		RzList *flags = rz_flag_tags_get(core->flags, tag);
		if (!flags) {
			pj_end(pj);
			break;
		}
		RzListIter *iter;
		RzFlagItem *flag;
		rz_list_foreach (flags, iter, flag) {
			pj_s(pj, flag->name);
		}
		pj_end(pj);
		rz_list_free(flags);
		break;
	}
	case RZ_OUTPUT_MODE_LONG: {
		rz_cons_printf("%s:\n", tag);
		RzList *flags = rz_flag_tags_get(core->flags, tag);
		if (!flags) {
			break;
		}
		RzListIter *iter;
		RzFlagItem *flag;
		rz_list_foreach (flags, iter, flag) {
			rz_cons_printf("0x%08" PFMT64x "  %s\n", flag->offset, flag->name);
		}
		rz_list_free(flags);
		break;
	}
	case RZ_OUTPUT_MODE_STANDARD:
		rz_cons_printf("%s\n", tag);
		break;
	default:
		rz_warn_if_reached();
		break;
	}
}

RZ_IPI RzCmdStatus rz_flag_tag_list_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	RzList *list = rz_flag_tags_list(core->flags);
	if (!list) {
		return RZ_CMD_STATUS_ERROR;
	}
	RzListIter *iter;
	const char *tag;
	rz_cmd_state_output_array_start(state);
	rz_list_foreach (list, iter, tag) {
		flag_tag_print(core, tag, state);
	}
	rz_cmd_state_output_array_end(state);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_flag_tag_search_handler(RzCore *core, int argc, const char **argv) {
	RzList *flags = rz_flag_tags_get(core->flags, argv[1]);
	if (!flags) {
		return RZ_CMD_STATUS_ERROR;
	}
	RzListIter *iter;
	RzFlagItem *flag;
	rz_list_foreach (flags, iter, flag) {
		rz_cons_printf("0x%08" PFMT64x "  %s\n", flag->offset, flag->name);
	}
	return RZ_CMD_STATUS_OK;
}

struct rename_flag_t {
	RzCore *core;
	const char *pfx;
	int count;
};

static bool rename_flag_ordinal(RzFlagItem *fi, void *user) {
	struct rename_flag_t *u = (struct rename_flag_t *)user;
	char *newName = rz_str_newf("%s%d", u->pfx, u->count++);
	if (!newName) {
		return false;
	}
	rz_flag_rename(u->core->flags, fi, newName);
	free(newName);
	return true;
}

static void flag_ordinals(RzCore *core, const char *glob) {
	char *pfx = strdup(glob);
	char *p = strchr(pfx, '*');
	if (p) {
		*p = 0;
	}
	struct rename_flag_t u = { .core = core, .pfx = pfx, .count = 0 };
	rz_flag_foreach_glob(core->flags, glob, rename_flag_ordinal, &u);
	free(pfx);
}

struct find_flag_t {
	RzFlagItem *win;
	ut64 at;
};

static bool find_flag_after(RzFlagItem *flag, void *user) {
	struct find_flag_t *u = (struct find_flag_t *)user;
	if (flag->offset > u->at && (!u->win || flag->offset < u->win->offset)) {
		u->win = flag;
	}
	return true;
}

static bool find_flag_after_foreach(RzFlagItem *flag, void *user) {
	if (flag->size != 0) {
		return true;
	}

	RzFlag *flags = (RzFlag *)user;
	struct find_flag_t u = { .win = NULL, .at = flag->offset };
	rz_flag_foreach(flags, find_flag_after, &u);
	if (u.win) {
		flag->size = u.win->offset - flag->offset;
	}
	return true;
}

static bool adjust_offset(RzFlagItem *flag, void *user) {
	st64 base = *(st64 *)user;
	flag->offset += base;
	return true;
}

static void print_space_stack(RzFlag *f, int ordinal, const char *name, bool selected, RzCmdStateOutput *state) {
	switch (state->mode) {
	case RZ_OUTPUT_MODE_JSON: {
		char *ename = rz_str_escape(name);
		if (!ename) {
			return;
		}
		pj_o(state->d.pj);
		pj_ki(state->d.pj, "ordinal", ordinal);
		pj_ks(state->d.pj, "name", ename);
		pj_kb(state->d.pj, "selected", selected);
		pj_end(state->d.pj);
		free(ename);
		break;
	}
	default:
		rz_cons_printf("%-2d %s%s\n", ordinal, name, selected ? " (selected)" : "");
		break;
	}
}

typedef struct {
	int rad;
	PJ *pj;
	RzAnalysisFunction *fcn;
} PrintFcnLabelsCtx;

static bool print_function_labels_cb(void *user, const ut64 addr, const void *v) {
	const PrintFcnLabelsCtx *ctx = user;
	const char *name = v;
	switch (ctx->rad) {
	case '*':
	case 1:
		rz_cons_printf("f.%s@0x%08" PFMT64x "\n", name, addr);
		break;
	case 'j':
		pj_kn(ctx->pj, name, addr);
		break;
	default:
		rz_cons_printf("0x%08" PFMT64x " %s   [%s + %" PFMT64d "]\n",
			addr,
			name, ctx->fcn->name,
			addr - ctx->fcn->addr);
	}
	return true;
}

static void print_function_labels_for(RzAnalysisFunction *fcn, int rad, PJ *pj) {
	rz_return_if_fail(fcn && (rad != 'j' || pj));
	bool json = rad == 'j';
	if (json) {
		pj_o(pj);
	}
	PrintFcnLabelsCtx ctx = { rad, pj, fcn };
	ht_up_foreach(fcn->labels, print_function_labels_cb, &ctx);
	if (json) {
		pj_end(pj);
	}
}

static void print_function_labels(RzAnalysis *analysis, RzAnalysisFunction *fcn, int rad) {
	rz_return_if_fail(analysis || fcn);
	PJ *pj = NULL;
	bool json = rad == 'j';
	if (json) {
		pj = pj_new();
	}
	if (fcn) {
		print_function_labels_for(fcn, rad, pj);
	} else {
		if (json) {
			pj_o(pj);
		}
		RzAnalysisFunction *f;
		RzListIter *iter;
		rz_list_foreach (analysis->fcns, iter, f) {
			if (!f->labels->count) {
				continue;
			}
			if (json) {
				pj_k(pj, f->name);
			}
			print_function_labels_for(f, rad, pj);
		}
		if (json) {
			pj_end(pj);
		}
	}
	if (json) {
		rz_cons_println(pj_string(pj));
		pj_free(pj);
	}
}

RZ_IPI RzCmdStatus rz_flag_space_add_handler(RzCore *core, int argc, const char **argv) {
	return bool2status(rz_flag_space_set(core->flags, argv[1]));
}

RZ_IPI RzCmdStatus rz_flag_space_list_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	rz_core_spaces_print(core, &core->flags->spaces, state);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_flag_space_move_handler(RzCore *core, int argc, const char **argv) {
	RzFlagItem *f = rz_flag_get_i(core->flags, core->offset);
	if (!f) {
		RZ_LOG_ERROR("Cannot find any flag at 0x%" PFMT64x ".\n", core->offset);
		return RZ_CMD_STATUS_ERROR;
	}
	f->space = rz_flag_space_cur(core->flags);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_flag_space_remove_handler(RzCore *core, int argc, const char **argv) {
	const RzSpace *sp = rz_flag_space_cur(core->flags);
	if (!sp) {
		RZ_LOG_ERROR("No flag space currently selected.\n");
		return RZ_CMD_STATUS_ERROR;
	}
	return bool2status(rz_flag_space_unset(core->flags, sp->name));
}

RZ_IPI RzCmdStatus rz_flag_space_remove_all_handler(RzCore *core, int argc, const char **argv) {
	return bool2status(rz_flag_space_unset(core->flags, NULL));
}

RZ_IPI RzCmdStatus rz_flag_space_rename_handler(RzCore *core, int argc, const char **argv) {
	return bool2status(rz_flag_space_rename(core->flags, NULL, argv[1]));
}

RZ_IPI RzCmdStatus rz_flag_space_stack_push_handler(RzCore *core, int argc, const char **argv) {
	return bool2status(rz_flag_space_push(core->flags, argv[1]));
}

RZ_IPI RzCmdStatus rz_flag_space_stack_pop_handler(RzCore *core, int argc, const char **argv) {
	return bool2status(rz_flag_space_pop(core->flags));
}

RZ_IPI RzCmdStatus rz_flag_space_stack_list_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	RzListIter *iter;
	char *space;
	int i = 0;
	rz_list_foreach (core->flags->spaces.spacestack, iter, space) {
		print_space_stack(core->flags, i++, space, false, state);
	}
	const char *cur_name = rz_flag_space_cur_name(core->flags);
	print_space_stack(core->flags, i++, cur_name, true, state);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_flag_remove_handler(RzCore *core, int argc, const char **argv) {
	ut64 address = rz_num_math(core->num, argv[1]);
	return bool2status(rz_flag_move(core->flags, core->offset, address));
}

RZ_IPI RzCmdStatus rz_flag_alias_handler(RzCore *core, int argc, const char **argv) {
	RzFlagItem *fi = rz_flag_get(core->flags, argv[1]);
	if (!fi) {
		fi = rz_flag_set(core->flags, argv[1], core->offset, 1);
	}
	if (!fi) {
		RZ_LOG_ERROR("Cannot find flag '%s'\n", argv[1]);
		return RZ_CMD_STATUS_ERROR;
	}
	rz_flag_item_set_alias(fi, argv[2]);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_flag_base_handler(RzCore *core, int argc, const char **argv) {
	if (argc > 2) {
		RzFlag *f = core->flags;
		ut64 base = rz_num_math(core->num, argv[1]);
		rz_flag_foreach_glob(f, argv[2], adjust_offset, &base);
	} else {
		core->flags->base = rz_num_math(core->num, argv[1]);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_flag_distance_handler(RzCore *core, int argc, const char **argv) {
	rz_cons_printf("%d\n", flag_to_flag(core, argv[1]));
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_flag_move_handler(RzCore *core, int argc, const char **argv) {
	ut64 address = rz_num_math(core->num, argv[1]);
	return bool2status(rz_flag_move(core->flags, core->offset, address));
}

RZ_IPI RzCmdStatus rz_flag_realname_handler(RzCore *core, int argc, const char **argv) {
	if (argc < 2) {
		RzFlagItem *item = rz_flag_get_i(core->flags, core->offset);
		if (item) {
			rz_cons_printf("%s\n", item->realname);
		}
	} else {
		RzFlagItem *item = rz_flag_get(core->flags, argv[1]);
		if (!item && !strncmp(argv[1], "fcn.", 4)) {
			item = rz_flag_get(core->flags, argv[1] + 4);
		}
		if (!item) {
			RZ_LOG_ERROR("Cannot find flag '%s'\n", argv[1]);
			return RZ_CMD_STATUS_ERROR;
		}
		rz_flag_item_set_realname(item, argv[2]);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_flag_list_ascii_handler(RzCore *core, int argc, const char **argv) {
	if (argc > 1) {
		flagbars(core, argv[1]);
	} else {
		flagbars(core, NULL);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_flag_color_handler(RzCore *core, int argc, const char **argv) {
	RzFlagItem *fi = rz_flag_get(core->flags, argv[1]);
	if (!fi) {
		RZ_LOG_ERROR("Cannot find the flag '%s'\n", argv[1]);
		return RZ_CMD_STATUS_ERROR;
	}
	const char *ret = rz_flag_item_set_color(fi, argv[2]);
	if (ret) {
		rz_cons_println(ret);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_flag_comment_handler(RzCore *core, int argc, const char **argv) {
	RzFlagItem *item;
	if (argc > 2) {
		item = rz_flag_get(core->flags, argv[1]);
		if (!item) {
			RZ_LOG_ERROR("Cannot find flag with name '%s'\n", argv[1]);
			return RZ_CMD_STATUS_ERROR;
		}
		if (!strncmp(argv[2], "base64:", 7)) {
			char *dec = (char *)rz_base64_decode_dyn(argv[2] + 7, -1);
			if (!dec) {
				eprintf("Failed to decode base64-encoded string\n");
				return RZ_CMD_STATUS_ERROR;
			}
			rz_flag_item_set_comment(item, dec);
			free(dec);
		} else {
			rz_flag_item_set_comment(item, argv[2]);
		}
	} else {
		item = rz_flag_get_i(core->flags, rz_num_math(core->num, argv[1]));
		if (item && item->comment) {
			rz_cons_println(item->comment);
		} else {
			RZ_LOG_ERROR("Cannot find the flag\n");
			return RZ_CMD_STATUS_ERROR;
		}
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_flag_ordinals_handler(RzCore *core, int argc, const char **argv) {
	flag_ordinals(core, argv[1]);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_flag_rename_handler(RzCore *core, int argc, const char **argv) {
	RzFlagItem *item = rz_flag_get(core->flags, argv[1]);
	if (!item && !strncmp(argv[1], "fcn.", 4)) {
		item = rz_flag_get(core->flags, argv[1] + 4);
	}
	if (!item) {
		RZ_LOG_ERROR("Cannot find matching flag\n");
		return RZ_CMD_STATUS_ERROR;
	}
	if (!rz_flag_rename(core->flags, item, argv[2])) {
		RZ_LOG_ERROR("Invalid new flag name\n");
		return RZ_CMD_STATUS_ERROR;
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_flag_hexdump_handler(RzCore *core, int argc, const char **argv) {
	char cmd[128];
	ut64 address = rz_num_math(core->num, argv[1]);
	RzFlagItem *item = rz_flag_get_i(core->flags, address);
	if (!item) {
		RZ_LOG_ERROR("Cannot find flag '%s'\n", argv[1]);
		return RZ_CMD_STATUS_ERROR;
	}
	rz_cons_printf("0x%08" PFMT64x "\n", item->offset);
	// FIXME: Use the API directly instead of calling the command
	snprintf(cmd, sizeof(cmd), "px@%" PFMT64d ":%" PFMT64d, item->offset, item->size);
	rz_core_cmd0(core, cmd);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI int rz_cmd_flag(void *data, const char *input) {
	RzCore *core = (RzCore *)data;
	ut64 off = core->offset;
	char *str = NULL;
	RzFlagItem *item;

	// TODO: off+=cursor
	if (*input) {
		str = strdup(input + 1);
	}
rep:
	switch (*input) {
	case 'V': // visual marks
		switch (input[1]) {
		case '-':
			rz_core_visual_mark_reset(core);
			break;
		case ' ': {
			int n = atoi(input + 1);
			if (n + ASCII_MAX + 1 < UT8_MAX) {
				const char *arg = strchr(input + 2, ' ');
				ut64 addr = arg ? rz_num_math(core->num, arg) : core->offset;
				rz_core_visual_mark_set(core, n + ASCII_MAX + 1, addr);
			}
		} break;
		case '?':
			eprintf("Usage: fV[*-] [nkey] [offset]\n");
			eprintf("Dump/Restore visual marks (mK/'K)\n");
			break;
		default:
			rz_core_visual_mark_dump(core);
			break;
		}
		break;
	case 'R': // "fR"
		switch (*str) {
		case '\0':
			eprintf("Usage: fR [from] [to] ([mask])\n");
			eprintf("Example to relocate PIE flags on debugger:\n"
				" > fR entry0 `dm~:1[1]`\n");
			break;
		case '?':
			rz_cons_println("Usage: fR [from] [to] ([mask])");
			rz_cons_println("Example to relocate PIE flags on debugger:\n"
					" > fR entry0 `dm~:1[1]`");
			break;
		default: {
			char *p = strchr(str + 1, ' ');
			ut64 from, to, mask = 0xffff;
			int ret;
			if (p) {
				char *q = strchr(p + 1, ' ');
				*p = 0;
				if (q) {
					*q = 0;
					mask = rz_num_math(core->num, q + 1);
				}
				from = rz_num_math(core->num, str + 1);
				to = rz_num_math(core->num, p + 1);
				ret = rz_flag_relocate(core->flags, from, mask, to);
				eprintf("Relocated %d flags\n", ret);
			} else {
				eprintf("Usage: fR [from] [to] ([mask])\n");
				eprintf("Example to relocate PIE flags on debugger:\n"
					" > fR entry0 `dm~:1[1]`\n");
			}
		}
		}
		break;
	case '+': // "f+'
	case ' ': {
		const char *cstr = rz_str_trim_head_ro(str);
		char *eq = strchr(cstr, '=');
		char *b64 = strstr(cstr, "base64:");
		char *s = strchr(cstr, ' ');
		char *s2 = NULL, *s3 = NULL;
		char *comment = NULL;
		bool comment_needs_free = false;
		ut32 bsze = 1; // core->blocksize;
		int eqdir = 0;

		if (eq && eq > cstr) {
			char *prech = eq - 1;
			if (*prech == '+') {
				eqdir = 1;
				*prech = 0;
			} else if (*prech == '-') {
				eqdir = -1;
				*prech = 0;
			}
		}

		// Get outta here as fast as we can so we can make sure that the comment
		// buffer used on later code can be freed properly if necessary.
		if (*cstr == '.') {
			input++;
			goto rep;
		}
		// Check base64 padding
		if (eq && !(b64 && eq > b64 && (eq[1] == '\0' || (eq[1] == '=' && eq[2] == '\0')))) {
			*eq = 0;
			ut64 arg = rz_num_math(core->num, eq + 1);
			RzFlagItem *item = rz_flag_get(core->flags, cstr);
			if (eqdir && item) {
				off = item->offset + (arg * eqdir);
			} else {
				off = arg;
			}
		}
		if (s) {
			*s = '\0';
			s2 = strchr(s + 1, ' ');
			if (s2) {
				*s2 = '\0';
				if (s2[1] && s2[2]) {
					off = rz_num_math(core->num, s2 + 1);
				}
				s3 = strchr(s2 + 1, ' ');
				if (s3) {
					*s3 = '\0';
					if (!strncmp(s3 + 1, "base64:", 7)) {
						comment = (char *)rz_base64_decode_dyn(s3 + 8, -1);
						comment_needs_free = true;
					} else if (s3[1]) {
						comment = s3 + 1;
					}
				}
			}
			bsze = (s[1] == '=') ? 1 : rz_num_math(core->num, s + 1);
		}

		bool addFlag = true;
		if (input[0] == '+') {
			if ((item = rz_flag_get_at(core->flags, off, false))) {
				addFlag = false;
			}
		}
		if (addFlag) {
			item = rz_flag_set(core->flags, cstr, off, bsze);
		}
		if (item && comment) {
			rz_flag_item_set_comment(item, comment);
			if (comment_needs_free) {
				free(comment);
			}
		}
	} break;
	case '-':
		if (input[1] == '-') {
			rz_flag_unset_all(core->flags);
		} else if (input[1]) {
			const char *flagname = rz_str_trim_head_ro(input + 1);
			while (*flagname == ' ') {
				flagname++;
			}
			if (*flagname == '.') {
				RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis, off, 0);
				if (fcn) {
					rz_analysis_function_delete_label_at(fcn, off);
				} else {
					eprintf("Cannot find function at 0x%08" PFMT64x "\n", off);
				}
			} else {
				if (strchr(flagname, '*')) {
					rz_flag_unset_glob(core->flags, flagname);
				} else {
					rz_flag_unset_name(core->flags, flagname);
				}
			}
		} else {
			rz_flag_unset_off(core->flags, off);
		}
		break;
	case '.': // "f."
		input = rz_str_trim_head_ro(input + 1) - 1;
		if (input[1]) {
			if (input[1] == '*' || input[1] == 'j') {
				if (input[2] == '*') {
					print_function_labels(core->analysis, NULL, input[1]);
				} else {
					RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis, off, 0);
					if (fcn) {
						print_function_labels(core->analysis, fcn, input[1]);
					} else {
						eprintf("Cannot find function at 0x%08" PFMT64x "\n", off);
					}
				}
			} else {
				char *name = strdup(input + ((input[2] == ' ') ? 2 : 1));
				RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis, off, 0);
				if (name) {
					char *eq = strchr(name, '=');
					if (eq) {
						*eq = 0;
						off = rz_num_math(core->num, eq + 1);
					}
					rz_str_trim(name);
					if (fcn) {
						if (*name == '-') {
							rz_analysis_function_delete_label(fcn, name + 1);
						} else {
							rz_analysis_function_set_label(fcn, name, off);
						}
					} else {
						eprintf("Cannot find function at 0x%08" PFMT64x "\n", off);
					}
					free(name);
				}
			}
		} else {
			RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis, off, 0);
			if (fcn) {
				print_function_labels(core->analysis, fcn, 0);
			} else {
				eprintf("Local flags require a function to work.");
			}
		}
		break;
	case 'l': // "fl"
		if (input[1] == '?') { // "fl?"
			eprintf("Usage: fl[a] [flagname] [flagsize]\n");
		} else if (input[1] == 'a') { // "fla"
			// TODO: we can optimize this if core->flags->flags is sorted by flagitem->offset
			char *glob = strchr(input, ' ');
			if (glob) {
				glob++;
			}
			rz_flag_foreach_glob(core->flags, glob, find_flag_after_foreach, core->flags);
		} else if (input[1] == ' ') { // "fl ..."
			char *p, *arg = strdup(input + 2);
			rz_str_trim(arg);
			p = strchr(arg, ' ');
			if (p) {
				*p++ = 0;
				item = rz_flag_get_i(core->flags,
					rz_num_math(core->num, arg));
				if (item)
					item->size = rz_num_math(core->num, p);
			} else {
				if (*arg) {
					item = rz_flag_get_i(core->flags, core->offset);
					if (item) {
						item->size = rz_num_math(core->num, arg);
					}
				} else {
					item = rz_flag_get_i(core->flags, rz_num_math(core->num, arg));
					if (item) {
						rz_cons_printf("0x%08" PFMT64x "\n", item->size);
					}
				}
			}
			free(arg);
		} else { // "fl"
			item = rz_flag_get_i(core->flags, core->offset);
			if (item)
				rz_cons_printf("0x%08" PFMT64x "\n", item->size);
		}
		break;
	case ',': // "f,"
		cmd_flag_table(core, input);
		break;
	case 'g': // "fg"
		switch (input[1]) {
		case '*':
			__flag_graph(core, rz_str_trim_head_ro(input + 2), '*');
			break;
		case ' ':
			__flag_graph(core, rz_str_trim_head_ro(input + 2), ' ');
			break;
		case 0:
			__flag_graph(core, rz_str_trim_head_ro(input + 1), 0);
			break;
		default:
			eprintf("Usage: fg[*] ([prefix])\n");
			break;
		}
		break;
	case 'N':
		if (!input[1]) {
			RzFlagItem *item = rz_flag_get_i(core->flags, core->offset);
			if (item) {
				rz_cons_printf("%s\n", item->realname);
			}
			break;
		} else if (input[1] == ' ' && input[2]) {
			RzFlagItem *item;
			char *name = str + 1;
			char *realname = strchr(name, ' ');
			if (realname) {
				*realname = 0;
				realname++;
				item = rz_flag_get(core->flags, name);
				if (!item && !strncmp(name, "fcn.", 4)) {
					item = rz_flag_get(core->flags, name + 4);
				}
			} else {
				realname = name;
				item = rz_flag_get_i(core->flags, core->offset);
			}
			if (item) {
				rz_flag_item_set_realname(item, realname);
			}
			break;
		}
		eprintf("Usage: fN [[name]] [[realname]]\n");
		break;
	case '\0':
	case 'n': // "fn" "fnj"
	case '*': // "f*"
	case 'j': // "fj"
	case 'q': // "fq"
		if (input[0]) {
			switch (input[1]) {
			case 'j':
			case 'q':
			case 'n':
			case '*':
				input++;
				break;
			}
		}
		if (input[0] && input[1] == '.') {
			const int mode = input[2];
			const RzList *list = rz_flag_get_list(core->flags, core->offset);
			PJ *pj = NULL;
			if (mode == 'j') {
				pj = pj_new();
				pj_a(pj);
			}
			RzListIter *iter;
			RzFlagItem *item;
			rz_list_foreach (list, iter, item) {
				switch (mode) {
				case '*':
					rz_cons_printf("f %s = 0x%08" PFMT64x "\n", item->name, item->offset);
					break;
				case 'j': {
					pj_o(pj);
					pj_ks(pj, "name", item->name);
					pj_ks(pj, "realname", item->realname);
					pj_kn(pj, "offset", item->offset);
					pj_kn(pj, "size", item->size);
					pj_end(pj);
				} break;
				default:
					rz_cons_printf("%s\n", item->name);
					break;
				}
			}
			if (mode == 'j') {
				pj_end(pj);
				char *s = pj_drain(pj);
				rz_cons_printf("%s\n", s);
				free(s);
			}
		} else {
			rz_flag_list(core->flags, *input, input[0] ? input + 1 : "");
		}
		break;
	case 'i': // "fi"
		if (input[1] == ' ' || (input[1] && input[2] == ' ')) {
			char *arg = strdup(rz_str_trim_head_ro(input + 2));
			if (*arg) {
				arg = strdup(rz_str_trim_head_ro(input + 2));
				char *sp = strchr(arg, ' ');
				if (!sp) {
					char *newarg = rz_str_newf("%c0x%" PFMT64x " %s+0x%" PFMT64x,
						input[1], core->offset, arg, core->offset);
					free(arg);
					arg = newarg;
				} else {
					char *newarg = rz_str_newf("%c%s", input[1], arg);
					free(arg);
					arg = newarg;
				}
			} else {
				free(arg);
				arg = rz_str_newf(" 0x%" PFMT64x " 0x%" PFMT64x,
					core->offset, core->offset + core->blocksize);
			}
			rz_flag_list(core->flags, 'i', arg);
			free(arg);
		} else {
			// XXX dupe for prev case
			char *arg = rz_str_newf(" 0x%" PFMT64x " 0x%" PFMT64x,
				core->offset, core->offset + core->blocksize);
			rz_flag_list(core->flags, 'i', arg);
			free(arg);
		}
		break;
	default:
		break;
	}
	free(str);
	return 0;
}
