#ifndef _SCRIPTABLE_H_
#define _SCRIPTABLE_H_

#include "BasicPlugin.h"

extern bool hasMethod(NPObject *obj, NPIdentifier methodName);
extern bool invoke(NPObject *obj, NPIdentifier methodName,const NPVariant *args,uint32_t argCount,NPVariant *result);
extern NPObject *allocate(NPP npp, NPClass *aClass);
extern void deallocate(NPObject *npobj);

typedef struct PluginObject{
	struct NPObject npobj;
	NPP npp;
}PluginObject;


#endif /* _SCRIPTABLE_H_ */
