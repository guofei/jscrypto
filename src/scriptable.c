#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

#include "scriptable.h"
#include "jsrsa.h"

typedef struct PluginObject{
	NPObject npobj;
	NPP npp;
}PluginObject;

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
		if(argCount != 1 || !NPVARIANT_IS_STRING(args[0]))
			goto error;
		NPString str = NPVARIANT_TO_STRING(args[0]);
		const char *path = strndup((char *)str.UTF8Characters, str.UTF8Length);
		RSA *rsa = generate_rsa_key_to_file(path, PUBLIC_KEY, NULL);
		
	default:
		return false;
	}
error:
	INT32_TO_NPVARIANT(-1, *result);
	return false;
}

NPObject *allocate(NPP npp, NPClass *aClass)
{
	PluginObject *obj = malloc(sizeof(PluginObject));
	//obj->npobj._class = aClass;
	//obj->npobj.referenceCount = 1;
	obj->npp = npp;
	return (NPObject *)obj;
}

void deallocate(NPObject *npobj)
{
	PluginObject *obj = (PluginObject *)npobj;
	free(obj);
}
