#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

#include "scriptable.h"
#include "jsrsa.h"

typedef struct PluginObject{
	struct NPObject npobj;
	NPP npp;
}PluginObject;

#define LEN_OF_FUNCNAME 50

typedef enum __FUNCNAMES{
	LOAD_PUBLIC_KEY = 1,
	LOAD_PRIVATE_KEY,
	ENCRYPT,
	DECRYPT,
	TEST,
	NUM_OF_FUNCS
}FUNCNAMES;

static char arrayFuncNames[NUM_OF_FUNCS][LEN_OF_FUNCNAME] = {
	{""},
	{"load_public_key"},
	{"load_private_key"},
	{"encrypt"},
	{"decrypt"},
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
	PluginObject *pobj = (PluginObject *)obj;
	InstanceData *instanceData = pobj->npp->pdata;

	switch(nType){
	case LOAD_PUBLIC_KEY:
	{
		if(argCount != 1 || !NPVARIANT_IS_STRING(args[0]))
			goto error;
		char *path = NULL;
		NPString str = NPVARIANT_TO_STRING(args[0]);
		path = malloc(str.UTF8Length + 1);
		strncpy(path, (char *)str.UTF8Characters, str.UTF8Length);
		path[str.UTF8Length] = 0;
		RSA *rsa = read_rsa_key_from_file(path, PUBLIC_KEY, NULL);
		if(rsa == NULL)
			goto error;
		free(path);
		int i = keys_push(instanceData->keys, rsa);
		INT32_TO_NPVARIANT(i, *result);
		return true;
	}
	case LOAD_PRIVATE_KEY:
	{
		if(!NPVARIANT_IS_STRING(args[0]))
			goto error;
		char *path = NULL;
		char *password = NULL;

		NPString str = NPVARIANT_TO_STRING(args[0]);
		path = malloc(str.UTF8Length + 1);
		strncpy(path, (char *)str.UTF8Characters, str.UTF8Length);
		path[str.UTF8Length] = 0;
		if(argCount == 2){
			if(!NPVARIANT_IS_STRING(args[1]))
				goto error;

			NPString str = NPVARIANT_TO_STRING(args[1]);
			password = malloc(str.UTF8Length + 1);
			strncpy(password, (char *)str.UTF8Characters, str.UTF8Length);
			password[str.UTF8Length] = 0;
		}
		RSA *rsa = read_rsa_key_from_file(path, PRIVATE_KEY, password);
		if(rsa == NULL)
			goto error;
		free(path);
		free(password);
		int i = keys_push(instanceData->keys, rsa);
		INT32_TO_NPVARIANT(i, *result);
		return true;
	}
	case ENCRYPT:
	{
		if(argCount != 2 || (!NPVARIANT_IS_INT32(args[0]) && !NPVARIANT_IS_DOUBLE(args[0])) || !NPVARIANT_IS_STRING(args[1]))
			goto error;

		int key_index = 0;
		if(NPVARIANT_IS_INT32(args[0]))
			key_index = NPVARIANT_TO_INT32(args[0]);
		else if(NPVARIANT_IS_DOUBLE(args[0]))
			key_index = NPVARIANT_TO_DOUBLE(args[0]);
		NPString str = NPVARIANT_TO_STRING(args[1]);
		char *text = malloc(str.UTF8Length + 1);
		strncpy(text, (char *)str.UTF8Characters, str.UTF8Length);
		text[str.UTF8Length] = 0;
		char *data = public_encrypt(keys_get(instanceData->keys, key_index), text, str.UTF8Length);
		free(text);
		STRINGZ_TO_NPVARIANT(data, *result);
		return true;
	}
	case DECRYPT:
	{
		if(argCount != 2 || (!NPVARIANT_IS_INT32(args[0]) && !NPVARIANT_IS_DOUBLE(args[0])) || !NPVARIANT_IS_STRING(args[1]))
			goto error;

		int key_index = 0;
		if(NPVARIANT_IS_INT32(args[0]))
			key_index = NPVARIANT_TO_INT32(args[0]);
		else if(NPVARIANT_IS_DOUBLE(args[0]))
			key_index = NPVARIANT_TO_DOUBLE(args[0]);
		NPString str = NPVARIANT_TO_STRING(args[1]);
		char *text = malloc(str.UTF8Length + 1);
		strncpy(text, (char *)str.UTF8Characters, str.UTF8Length);
		text[str.UTF8Length] = 0;
		char *data = private_decrypt(keys_get(instanceData->keys, key_index), text, str.UTF8Length);
		free(text);
		STRINGZ_TO_NPVARIANT(data, *result);
		return true;
	}
	default:
		return false;
	}
error:
	INT32_TO_NPVARIANT(-1, *result);
	return true;
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
