#include <uuid/uuid.h>
#include "uuid.h"

using namespace v8;

namespace uuid {

static Handle<Value> NewUuid(const Arguments& args)
{
    uuid_t  uu;
    char    out[36];

    uuid_generate_random(uu);
    uuid_unparse_lower(uu, out);

    return String::New(out, 36);
}

}

extern "C" {
    
Handle<FunctionTemplate> createObject()
{
    HandleScope handle_scope;
    Local<FunctionTemplate> uuid = FunctionTemplate::New(uuid::NewUuid);
    return handle_scope.Close(uuid);
}

}
