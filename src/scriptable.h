#ifndef _SCRIPTABLE_H_
#define _SCRIPTABLE_H_

#include "BasicPlugin.h"

extern bool hasMethod(NPObject *obj, NPIdentifier methodName);
extern bool invoke(NPObject *obj, NPIdentifier methodName,const NPVariant *args,uint32_t argCount,NPVariant *result);

#endif /* _SCRIPTABLE_H_ */
