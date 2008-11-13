#include <ClearSilver.h>
#include "clearsilver.h"
#include <iostream>

using namespace v8;
using namespace std;

static NEOERR *output(void *ctx, char *s) {
    HandleScope scope;
    Handle<Function> callback = *reinterpret_cast<Handle<Function>*>(ctx);
    Handle<Value> argv[1] = { String::New(s) };
    callback->Call(Context::GetCurrent()->Global(), 1, argv);
    return STATUS_OK;
}

static Handle<Value> Initialize(const Arguments& args)
{
    HandleScope scope;
    String::Utf8Value fname(args[0]);
    HDF *hdf;
    CSPARSE *parse;
    hdf_init(&hdf);
    cs_init(&parse, hdf);
    cs_parse_file(parse, *fname);
    Handle<External> hdf_ptr = External::New(hdf);
    Handle<External> parse_ptr = External::New(parse);
    args.This()->SetInternalField(0, hdf_ptr);
    args.This()->SetInternalField(1, parse_ptr);
    return True();
}

static Handle<Value> Set(const Arguments& args)
{
    HandleScope scope;
    Handle<Value> field = args.This()->GetInternalField(0);
    String::AsciiValue key(args[0]);
    String::Utf8Value value(args[1]);
    HDF *hdf= reinterpret_cast<HDF *>(Handle<External>::Cast(field)->Value());
    hdf_set_value(hdf, *key, *value);
    return True();
}

static Handle<Value> Render(const Arguments& args)
{
    HandleScope scope;
    Handle<Value> field = args.This()->GetInternalField(1);
    CSPARSE *parse = reinterpret_cast<CSPARSE *>(Handle<External>::Cast(field)->Value());
    Handle<Value> fun = args[0];
    Handle<Function> f = Handle<Function>::Cast(fun);
    cs_render(parse, &fun, output);
    return True();
}

static Handle<Value> Destroy(const Arguments& args)
{
    HandleScope scope;
    Handle<Value> field0 = args.This()->GetInternalField(0);
    Handle<Value> field1 = args.This()->GetInternalField(1);
    HDF *hdf = reinterpret_cast<HDF *>(Handle<External>::Cast(field0)->Value());
    CSPARSE *parse = reinterpret_cast<CSPARSE *>(Handle<External>::Cast(field1)->Value());
    cs_destroy(&parse);
    hdf_destroy(&hdf);
    return True();
}

extern "C" {
    
Handle<String> getName()
{
    HandleScope scope;
    Handle<String> name = String::New("@v8com/ClearSilver;1");
    return scope.Close(name);
}

Handle<FunctionTemplate> createObject()
{
    HandleScope handle_scope;
    Handle<FunctionTemplate> result = FunctionTemplate::New(Initialize);
    result->SetClassName(getName());
    Handle<ObjectTemplate> instance = result->InstanceTemplate();
    instance->SetInternalFieldCount(2);
    Handle<ObjectTemplate> prototype = result->PrototypeTemplate();
    prototype->Set(String::New("set"), FunctionTemplate::New(Set));
    prototype->Set(String::New("render"), FunctionTemplate::New(Render));
    prototype->Set(String::New("destroy"), FunctionTemplate::New(Destroy));
    return handle_scope.Close(result);
}

}
