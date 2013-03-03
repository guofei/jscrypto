#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

#include "scriptable.h"
#include "jsrsa.h"

#define LEN_OF_FUNCNAME 50

typedef enum __FUNCNAMES{
	LOAD_PUBLIC_KEY = 1,
	LOAD_PRIVATE_KEY,
	ENCRYPT,
	DECRYPT,
	COUNTER_CREATE,
	COUNTER_ENCRYPT,
	COUNTER_DECRYPT,
	COUNTER_ENCRYPT_OR_DECRYPT,
	TEST,
	NUM_OF_FUNCS
}FUNCNAMES;

static char arrayFuncNames[NUM_OF_FUNCS][LEN_OF_FUNCNAME] = {
	{""},
	{"load_public_key"},
	{"load_private_key"},
	{"encrypt"},
	{"decrypt"},
	{"counter_create"},
	{"counter_encrypt"},
	{"counter_decrypt"},
	{"counter_encrypt_or_decrypt"},
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

static char *npstring_to_char(NPString s){
	char *ret = calloc(s.UTF8Length + 1, sizeof(char));
	strncpy(ret, (char *)s.UTF8Characters, s.UTF8Length);
	return ret;
}

bool invoke(NPObject *obj, NPIdentifier methodName,const NPVariant *args,uint32_t argCount,NPVariant *result){
	NPUTF8 *name = sBrowserFuncs->utf8fromidentifier(methodName);
	int nType = chkMethod(name);
	sBrowserFuncs->memfree(name);
	PluginObject *pobj = (PluginObject *)obj;
	InstanceData *instanceData = pobj->npp->pdata;

	switch(nType){
	case COUNTER_CREATE:
	{
		if(argCount != 1 || (!NPVARIANT_IS_INT32(args[0]) && !NPVARIANT_IS_DOUBLE(args[0])))
			goto error;

		int num = 0;
		if(NPVARIANT_IS_INT32(args[0]))
			num = NPVARIANT_TO_INT32(args[0]);
		else if(NPVARIANT_IS_DOUBLE(args[0]))
			num = NPVARIANT_TO_DOUBLE(args[0]);

		EVP_CIPHER_CTX *ctx = cipher_ctx_new("test");
		unsigned char *c = counter_new(num, ctx);
		cipher_ctx_free(ctx);
		INT32_TO_NPVARIANT(NP_Array_push(instanceData->counter_array, c), *result);
		
		return true;
	}
	case COUNTER_ENCRYPT:
	{
		if(argCount != 3
		   || !NPVARIANT_IS_STRING(args[0])
		   || !NPVARIANT_IS_STRING(args[1])
		   || (!NPVARIANT_IS_INT32(args[2]) && !NPVARIANT_IS_DOUBLE(args[2])))
			goto error;

		char *password = npstring_to_char(NPVARIANT_TO_STRING(args[0]));
		char *text = npstring_to_char(NPVARIANT_TO_STRING(args[1]));
		int counter = -1;
		if(NPVARIANT_IS_INT32(args[2]))
			counter = NPVARIANT_TO_INT32(args[2]);
		else if(NPVARIANT_IS_DOUBLE(args[2]))
			counter = NPVARIANT_TO_DOUBLE(args[2]);

		char *cipher_text;
		counter_encrypt(password, text, &cipher_text, strlen(text), NP_Array_get(instanceData->counter_array, counter));
		free(text);
		free(password);
		STRINGZ_TO_NPVARIANT(cipher_text, *result);
		return true;
	}
	case COUNTER_DECRYPT:
	{
		if(argCount != 3
		   || !NPVARIANT_IS_STRING(args[0])
		   || !NPVARIANT_IS_STRING(args[1])
		   || (!NPVARIANT_IS_INT32(args[2]) && !NPVARIANT_IS_DOUBLE(args[2])))
			goto error;
		char *password = npstring_to_char(NPVARIANT_TO_STRING(args[0]));
		char *text = npstring_to_char(NPVARIANT_TO_STRING(args[1]));
		int counter = -1;
		if(NPVARIANT_IS_INT32(args[2]))
			counter = NPVARIANT_TO_INT32(args[2]);
		else if(NPVARIANT_IS_DOUBLE(args[2]))
			counter = NPVARIANT_TO_DOUBLE(args[2]);

		char *ret;
		counter_encrypt(password, text, &ret, strlen(text), NP_Array_get(instanceData->counter_array, counter));
		free(text);
		free(password);
		STRINGZ_TO_NPVARIANT(ret, *result);
		return true;
	}
	case LOAD_PUBLIC_KEY:
	{
		if(argCount != 1 || !NPVARIANT_IS_STRING(args[0]))
			goto error;
		char *path = npstring_to_char(NPVARIANT_TO_STRING(args[0]));
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
		char *path = npstring_to_char(NPVARIANT_TO_STRING(args[0]));
		char *password = NULL;
		
		if(argCount == 2){
			if(!NPVARIANT_IS_STRING(args[1]))
				goto error;

			password = npstring_to_char(NPVARIANT_TO_STRING(args[1]));
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

		char *text = npstring_to_char(NPVARIANT_TO_STRING(args[1]));
		char *data = public_encrypt(keys_get(instanceData->keys, key_index), text, strlen(text));
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

		char *text = npstring_to_char(NPVARIANT_TO_STRING(args[1]));
		char *data = private_decrypt(keys_get(instanceData->keys, key_index), text, strlen(text));
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
	//obj->npp = npp;
	return (NPObject *)obj;
}

void deallocate(NPObject *npobj)
{
	PluginObject *obj = (PluginObject *)npobj;
	free(obj);
}
