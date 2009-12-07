#include "uuid.h"
#include <cassert>

using namespace v8;
using namespace std;

int main(int argc, char* argv[])
{
    HandleScope scope;
    Local<ObjectTemplate> global = ObjectTemplate::New();
    Persistent<Context> ctx = Context::New(NULL, global);
    Context::Scope ctx_scope(ctx);

    Handle<FunctionTemplate> o = createObject();
    Handle<Value> v = o->GetFunction()->Call(global->NewInstance(), 0, NULL);
    String::AsciiValue u(v);

    assert(u.length() != 0);
    
    ctx.Dispose();

    return 0;
}
