#include "BasicPlugin.h"
#include "scriptable.h"
#include "jsrsa.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define PLUGIN_NAME        "Crypto Plug-in"
#define PLUGIN_DESCRIPTION PLUGIN_NAME " (Mozilla SDK)"
#define PLUGIN_VERSION     "1.0.0.0"

NPNetscapeFuncs* sBrowserFuncs = NULL;

typedef struct InstanceData {
	NPP npp;
	Keys keys;
	NPObject *pluginobject;
} InstanceData;

NP_EXPORT(NPError)
NP_Initialize(NPNetscapeFuncs* bFuncs, NPPluginFuncs* pFuncs)
{
	sBrowserFuncs = bFuncs;

	// Check the size of the provided structure based on the offset of the
	// last member we need.
	if (pFuncs->size < (offsetof(NPPluginFuncs, setvalue) + sizeof(void*)))
		return NPERR_INVALID_FUNCTABLE_ERROR;

	pFuncs->newp = NPP_New;
	pFuncs->destroy = NPP_Destroy;
	pFuncs->setwindow = NPP_SetWindow;
	pFuncs->newstream = NPP_NewStream;
	pFuncs->destroystream = NPP_DestroyStream;
	pFuncs->asfile = NPP_StreamAsFile;
	pFuncs->writeready = NPP_WriteReady;
	pFuncs->write = NPP_Write;
	pFuncs->print = NPP_Print;
	pFuncs->event = NPP_HandleEvent;
	pFuncs->urlnotify = NPP_URLNotify;
	pFuncs->getvalue = NPP_GetValue;
	pFuncs->setvalue = NPP_SetValue;

	return NPERR_NO_ERROR;
}

NP_EXPORT(char*)
NP_GetPluginVersion()
{
	return PLUGIN_VERSION;
}

NP_EXPORT(const char*)
NP_GetMIMEDescription()
{
	return "application/crypto:crypto:Crypto plugin";
}

NP_EXPORT(NPError)
NP_GetValue(void* future, NPPVariable aVariable, void* aValue) {
	switch (aVariable) {
	case NPPVpluginNameString:
		*((char**)aValue) = PLUGIN_NAME;
		break;
	case NPPVpluginDescriptionString:
		*((char**)aValue) = PLUGIN_DESCRIPTION;
		break;
	default:
		return NPERR_INVALID_PARAM;
		break;
	}
	return NPERR_NO_ERROR;
}

NP_EXPORT(NPError)
NP_Shutdown()
{
	return NPERR_NO_ERROR;
}

NPError
NPP_New(NPMIMEType pluginType, NPP instance, uint16_t mode, int16_t argc, char* argn[], char* argv[], NPSavedData* saved) {
	// Make sure we can render this plugin
	sBrowserFuncs->setvalue(instance, NPPVpluginWindowBool, (void*)false);

	// set up our our instance data
	InstanceData* instanceData = (InstanceData*)malloc(sizeof(InstanceData));
	if (!instanceData)
		return NPERR_OUT_OF_MEMORY_ERROR;
	memset(instanceData, 0, sizeof(InstanceData));

	struct NPClass PluginClass = {NP_CLASS_STRUCT_VERSION, NULL, NULL, NULL, hasMethod, invoke, NULL, NULL,	NULL, NULL, NULL, NULL};
	instanceData->npp = instance;
	instanceData->keys = keys_new();
	instanceData->pluginobject = sBrowserFuncs->createobject(instance,&PluginClass);
	instance->pdata = instanceData;

	return NPERR_NO_ERROR;
}

NPError
NPP_Destroy(NPP instance, NPSavedData** save) {
	InstanceData* instanceData = (InstanceData*)(instance->pdata);
	keys_free(instanceData->keys);
	free(instanceData);
	return NPERR_NO_ERROR;
}

NPError
NPP_SetWindow(NPP instance, NPWindow* window) {
	return NPERR_NO_ERROR;
}

NPError
NPP_NewStream(NPP instance, NPMIMEType type, NPStream* stream, NPBool seekable, uint16_t* stype) {
	return NPERR_GENERIC_ERROR;
}

NPError
NPP_DestroyStream(NPP instance, NPStream* stream, NPReason reason) {
	return NPERR_GENERIC_ERROR;
}

int32_t
NPP_WriteReady(NPP instance, NPStream* stream) {
	return 0;
}

int32_t
NPP_Write(NPP instance, NPStream* stream, int32_t offset, int32_t len, void* buffer) {
	return 0;
}

void
NPP_StreamAsFile(NPP instance, NPStream* stream, const char* fname) {

}

void
NPP_Print(NPP instance, NPPrint* platformPrint) {

}

int16_t
NPP_HandleEvent(NPP instance, void* event) {
	return 0;
}

void
NPP_URLNotify(NPP instance, const char* URL, NPReason reason, void* notifyData) {

}

NPError
NPP_GetValue(NPP instance, NPPVariable variable, void *value) {
	if (variable == NPPVpluginScriptableNPObject) {
		void **v = (void **)value;

		InstanceData *p = instance->pdata;
		NPObject *pluginobject = p->pluginobject;

		if (pluginobject)
			sBrowserFuncs->retainobject(pluginobject);

		*v = pluginobject;
		return NPERR_NO_ERROR;
	}
	return NPERR_GENERIC_ERROR;
}

NPError
NPP_SetValue(NPP instance, NPNVariable variable, void *value) {
	return NPERR_GENERIC_ERROR;
}

