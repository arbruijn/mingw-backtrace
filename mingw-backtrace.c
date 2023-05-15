#include <windows.h>
#include <stdio.h>
#include <libbacktrace/backtrace.h>
#include "backtrace-supported.h"
#include <inttypes.h>
#include "unwind.h"
#include "config.h"
#include "libbacktrace/internal.h"

struct bt_ctx {
	struct backtrace_state *state;
	int error;
	FILE *log;
	const char *filename;
};

static int my_fileline_initialize(struct backtrace_state *state,
	backtrace_error_callback error_callback, void *data, const char *filename)
{
	int failed;
	fileline fileline_fn;
	int descriptor;
	int does_not_exist = 0;

	if (!state->threaded)
		failed = state->fileline_initialization_failed;
	else
		failed = backtrace_atomic_load_int (&state->fileline_initialization_failed);

	if (failed) {
			error_callback (data, "failed to read executable information", -1);
			return 0;
	}

	if (!state->threaded)
		fileline_fn = state->fileline_fn;
	else
		fileline_fn = backtrace_atomic_load_pointer (&state->fileline_fn);
	if (fileline_fn != NULL)
		return 1;

	if (filename == NULL)
		return 1;

	descriptor = backtrace_open (filename, error_callback, data,
			&does_not_exist);
	if (descriptor < 0) {
		if (does_not_exist)
				error_callback (data, filename, ENOENT);
		failed = 1;
	}

	if (!failed) {
		if (!backtrace_initialize (state, filename, descriptor, error_callback,
			data, &fileline_fn))
		failed = 1;
	}

	if (failed) {
		if (!state->threaded)
			state->fileline_initialization_failed = 1;
		else
			backtrace_atomic_store_int (&state->fileline_initialization_failed, 1);
		return 0;
	}

	if (!state->threaded)
		state->fileline_fn = fileline_fn;
	else {
		backtrace_atomic_store_pointer (&state->fileline_fn, fileline_fn);

		/* Note that if two threads initialize at once, one of the data
			 sets may be leaked.	*/
	}

	return 1;
}

int my_backtrace_syminfo (struct backtrace_state *state, uintptr_t pc,
			 backtrace_syminfo_callback callback,
			 backtrace_error_callback error_callback, void *data, const char *filename)
{
	if (!my_fileline_initialize (state, error_callback, data, filename))
		return 0;

	if (state->fileline_initialization_failed)
		return 0;

	state->syminfo_fn (state, pc, callback, error_callback, data);
	return 1;
}

static void error_callback(void *data, const char *msg, int errnum)
{
	struct bt_ctx *ctx = data;
	fprintf(ctx->log, "ERROR: %s (%d)", msg, errnum);
	ctx->error = 1;
}

static void syminfo_callback (void *data, uintptr_t pc, const char *symname, uintptr_t symval, uintptr_t symsize)
{
	struct bt_ctx *ctx = data;
	if (symname) {
		fprintf(ctx->log, "%" PRIxPTR " %s\n", pc, symname);
	} else {
		fprintf(ctx->log, "%" PRIxPTR " ??\n", pc);
	}
}

static int full_callback(void *data, uintptr_t pc, const char *filename, int lineno, const char *function)
{
	struct bt_ctx *ctx = data;
	if (function) {
		fprintf(ctx->log, "%" PRIxPTR " %s %s:%d\n", pc, function, filename?filename:"??", lineno);
	} else {
		my_backtrace_syminfo (ctx->state, pc, syminfo_callback, error_callback, data, ctx->filename);
	}
	return 0;
}


int my_backtrace_pcinfo (struct backtrace_state *state, uintptr_t pc,
									backtrace_full_callback callback,
									backtrace_error_callback error_callback, void *data,
									const char *filename)
{
	if (!my_fileline_initialize (state, error_callback, data, filename))
		return 0;

	if (state->fileline_initialization_failed)
		return 0;

	return state->fileline_fn (state, pc, callback, error_callback, data);
}

static void bt(struct backtrace_state *state, LPEXCEPTION_POINTERS ep, FILE *log)
{
	struct bt_ctx btdata = {state, 0};
	UNWIND_HISTORY_TABLE ms_history;
	CONTEXT ctx;
	DISPATCHER_CONTEXT disp;
	HMODULE mod, last_mod = NULL;
	char filename[_MAX_PATH];

	btdata.log = log;
	ctx = *ep->ContextRecord;
	memset(&ms_history, 0, sizeof(ms_history));
	memset(&disp, 0, sizeof(disp));
	filename[0] = 0;
	btdata.filename = filename;
	while (ctx.Rip) {
		
		uintptr_t pc = ctx.Rip;
		pc--;
		if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
			(LPCSTR)pc, &mod))
			mod = NULL;
		if ((!filename[0] || mod != last_mod) && !GetModuleFileNameA(mod, filename, sizeof(filename)))
			break;
		last_mod = mod;
		IMAGE_DOS_HEADER *dh = (IMAGE_DOS_HEADER *)mod;
		uintptr_t base = 0;
		if (dh->e_magic == IMAGE_DOS_SIGNATURE) {
			IMAGE_NT_HEADERS *nh = (IMAGE_NT_HEADERS *)((BYTE *)dh + dh->e_lfanew);
			if (nh->Signature == IMAGE_NT_SIGNATURE && nh->FileHeader.SizeOfOptionalHeader) {
				base = nh->OptionalHeader.ImageBase;
			}
		}
		//printf("mod %p base %"PRIxPTR"\n", mod, base);
		if (mod && base)
			pc += base - (uintptr_t)mod;

		my_backtrace_pcinfo (state, pc, full_callback, error_callback, &btdata, filename);

		disp.ControlPc = ctx.Rip;
		disp.FunctionEntry = RtlLookupFunctionEntry(ctx.Rip, &disp.ImageBase, &ms_history);
		if (!disp.FunctionEntry)
			break;
		disp.LanguageHandler = RtlVirtualUnwind(0, disp.ImageBase, ctx.Rip, disp.FunctionEntry,
			&ctx, &disp.HandlerData, &disp.EstablisherFrame, NULL);
	}
}

static LONG WINAPI exceptionPrinter(LPEXCEPTION_POINTERS ep)
{
	char path[MAX_PATH], *p;
	HMODULE mod;
	char logpath[MAX_PATH];
	SYSTEMTIME lt;
	TIME_ZONE_INFORMATION tz;
	FILE *log;
	char modfile[MAX_PATH], *modname;
	PCONTEXT ctx;
	LONG Bias;
	DWORD code = ep->ExceptionRecord->ExceptionCode;
	
	GetModuleFileName(NULL, modfile, sizeof(modfile));
	modname = strrchr(modfile, '\\');
	modname = modname ? modname + 1 : modfile;
	if ((p = strrchr(modname, '.')))
		*p = 0;
	GetLocalTime(&lt);
	snprintf(logpath, sizeof(logpath), "%s\\%s-crash-%04d%02d%02d-%02d%02d%02d.txt", getenv("TEMP"),
		modname, lt.wYear, lt.wMonth, lt.wDay, lt.wHour, lt.wMinute, lt.wSecond);

	if (!(log = fopen(logpath, "w")))
		return EXCEPTION_EXECUTE_HANDLER;

	if (GetTimeZoneInformation(&tz) == TIME_ZONE_ID_DAYLIGHT)
		Bias = tz.Bias + tz.DaylightBias;
	else
		Bias = tz.Bias + tz.StandardBias;
	fprintf(log, "%s crashed at %04d-%02d-%02d %02d:%02d:%02d %c%02d%02d\n", modname,
		lt.wYear, lt.wMonth, lt.wDay, lt.wHour, lt.wMinute, lt.wSecond, Bias < 0 ? '+' : '-',
		(int)-Bias / 60, abs(Bias % 60));

	ctx = ep->ContextRecord;
		
	const char *desc = "";
	switch (code) {
#define EX_DESC(name) \
		case EXCEPTION_##name: desc = " (" #name ")"; \
													 break

		EX_DESC(ACCESS_VIOLATION);
		EX_DESC(ARRAY_BOUNDS_EXCEEDED);
		EX_DESC(BREAKPOINT);
		EX_DESC(DATATYPE_MISALIGNMENT);
		EX_DESC(FLT_DENORMAL_OPERAND);
		EX_DESC(FLT_DIVIDE_BY_ZERO);
		EX_DESC( FLT_INEXACT_RESULT);
		EX_DESC(FLT_INVALID_OPERATION);
		EX_DESC(FLT_OVERFLOW);
		EX_DESC(FLT_STACK_CHECK);
		EX_DESC(FLT_UNDERFLOW);
		EX_DESC(ILLEGAL_INSTRUCTION);
		EX_DESC(IN_PAGE_ERROR);
		EX_DESC(INT_DIVIDE_BY_ZERO);
		EX_DESC(INT_OVERFLOW);
		EX_DESC(INVALID_DISPOSITION);
		EX_DESC(NONCONTINUABLE_EXCEPTION);
		EX_DESC(PRIV_INSTRUCTION);
		EX_DESC(SINGLE_STEP);
		EX_DESC(STACK_OVERFLOW);
	}

	path[0] = 0;
	if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
		GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCSTR)ep->ContextRecord->Rip, &mod))
		GetModuleFileNameA(mod, path, sizeof(path));
	if ((p = strrchr(path, '\\')))
		p++;
	else
		p = path;

	fprintf(log, "code: 0x%08lX%s at %" PRIxPTR " in %s (%" PRIxPTR ")\n",
		code, desc, ep->ContextRecord->Rip, p, (uintptr_t)mod);

	if (code==EXCEPTION_ACCESS_VIOLATION && ep->ExceptionRecord->NumberParameters==2) {
		ULONG_PTR flag = ep->ExceptionRecord->ExceptionInformation[0];
		ULONG_PTR addr = ep->ExceptionRecord->ExceptionInformation[1];
		fprintf(log, "%s violation at 0x%p\n",
				flag == 8 ? "data execution prevention" :
					flag ? "write access" : "read access", (void*)addr);
	}

	fprintf(log, "\n");
	
	GetModuleFileName(NULL, path, sizeof(path));
	struct backtrace_state *state = backtrace_create_state (path, BACKTRACE_SUPPORTS_THREADS, error_callback, NULL);
	bt(state, ep, log);

	fprintf(log, "\n");
	fprintf(log, "rax %016llx rbx %016llx rcx %016llx rdx %016llx\nrsi %016llx rdi %016llx rbp %016llx rsp %016llx\n",
		ctx->Rax, ctx->Rbx, ctx->Rcx, ctx->Rdx, ctx->Rsi, ctx->Rdi, ctx->Rbp, ctx->Rsp);
	fprintf(log, "r8  %016llx r9  %016llx r10 %016llx r11 %016llx\nr12 %016llx r13 %016llx r14 %016llx r15 %016llx\n",
		ctx->R8, ctx->R9, ctx->R10, ctx->R11, ctx->R12, ctx->R13, ctx->R14, ctx->R15);

	fprintf(log, "\nstack:\n");
	long long *llp = (long long *)ctx->Rsp;
	for (int i = 0; i < 128; i += 2)
		if (!IsBadReadPtr(llp + i, 16))
			fprintf(log, "%016llx: %016llx  %016llx\n", (long long)(llp + i), llp[i], llp[i + 1]);

	fclose(log);

	ShellExecuteA(0, 0, logpath, 0, 0, SW_SHOW);

	return EXCEPTION_CONTINUE_SEARCH;
}

static LPTOP_LEVEL_EXCEPTION_FILTER ue_prev = NULL;

static void backtrace_register(void)
{
	ue_prev = SetUnhandledExceptionFilter(exceptionPrinter);
}

static void backtrace_unregister(void)
{
	SetUnhandledExceptionFilter(ue_prev);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpvReserved)
{
	switch (dwReason) {
	case DLL_PROCESS_ATTACH:
		backtrace_register();
		break;
	case DLL_PROCESS_DETACH:
		backtrace_unregister();
		break;
	}
	return TRUE;
}
