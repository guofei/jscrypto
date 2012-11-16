#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

#include "scriptable.h"

#define LEN_OF_FUNCNAME 50

typedef enum __FUNCNAMES{
	LOAD_PUBLIC_KEY = 1,
	LOAD_PRIVATE_KEY,
	TEST,
	NUM_OF_FUNCS
}FUNCNAMES;

static char arrayFuncNames[NUM_OF_FUNCS][LEN_OF_FUNCNAME] = {
	{ "" },
	{ "load_public_key" },
	{ "load_private_key" },
	{ "test" }
};

//enum __FUNNAMESが返る
int chkMethod(char *target)
{
	int nRet = 0;
	int i;

	for(i = 1; i < NUM_OF_FUNCS; i++){
		if(0 == strcmp(target, arrayFuncNames[i])){
			nRet = i;
			break;
		}
	}
	return nRet;
}

bool hasMethod(NPObject *obj, NPIdentifier methodName){
	NPUTF8 *name = sBrowserFuncs->utf8fromidentifier(methodName);

	bool result = false;
	int nFuncType = 0;
	if(0 < (nFuncType =  chkMethod(name))){
		result = true;
	}

	sBrowserFuncs->memfree(name);
	//  return 1;
	return result;
}

bool invoke(NPObject *obj, NPIdentifier methodName,const NPVariant *args,uint32_t argCount,NPVariant *result){
	NPUTF8 *name = sBrowserFuncs->utf8fromidentifier(methodName);
	int nType = chkMethod(name);
	sBrowserFuncs->memfree(name);

	switch(nType){
	case LOAD_PUBLIC_KEY:

	default:
		return false;
	}
}
