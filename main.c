#define FIT_IMPLEMENTATION
#include "fit.h"

static FIT_Context FIT_ctx;

int main(int argc, char *argv[]) {
	FIT_ContextInit(&FIT_ctx);
	int result = FIT_Run(&FIT_ctx, argc, argv);		 
	FIT_ContextDeinit(&FIT_ctx);
	return result;
};