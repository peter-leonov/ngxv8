#include <tcutil.h>
#include <tchdb.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include "tchdb.h"

using namespace v8;

static Handle<Value> Initialize(const Arguments& args)
{
    HandleScope scope;
    String::Utf8Value fname(args[0]);
    TCHDB *tchdb = tchdbnew();
    tchdbsetmutex(tchdb);
    tchdbopen(tchdb, *fname, HDBOWRITER | HDBOREADER | HDBOCREAT);
    Handle<External> tchdb_ptr = External::New(tchdb);
    args.This()->SetInternalField(0, tchdb_ptr);
    return True();
}

static Handle<Value> Put(const Arguments& args)
{
    HandleScope scope;
    Handle<Value> field = args.This()->GetInternalField(0);
    String::AsciiValue key(args[0]);
    String::Utf8Value value(args[1]);
    TCHDB *tchdb = reinterpret_cast<TCHDB *>(Handle<External>::Cast(field)->Value());
    bool rc = tchdbput2(tchdb, *key, *value);
    return rc ? True() : False();
}

static Handle<Value> Get(const Arguments& args)
{
    HandleScope scope;
    Handle<Value> field = args.This()->GetInternalField(0);
    String::AsciiValue key(args[0]);
    TCHDB *tchdb = reinterpret_cast<TCHDB *>(Handle<External>::Cast(field)->Value());
    char *value = tchdbget2(tchdb, *key);
    if (value == NULL) {
        return Undefined();
    }
    Handle<String> ret = String::New(value);
    free(value);
    return ret;
}

static Handle<Value> Close(const Arguments& args)
{
    HandleScope scope;
    Handle<Value> field = args.This()->GetInternalField(0);
    TCHDB *tchdb = reinterpret_cast<TCHDB *>(Handle<External>::Cast(field)->Value());
    tchdbclose(tchdb);
    tchdbdel(tchdb);
    return True();
}

extern "C" {
    
Handle<String> getName()
{
    HandleScope scope;
    Handle<String> name = String::New("@v8com/tokyocabinet/HDB;1");
    return scope.Close(name);
}

Handle<FunctionTemplate> createObject()
{
    HandleScope handle_scope;
    Handle<FunctionTemplate> result = FunctionTemplate::New(Initialize);
    result->SetClassName(getName());
    Handle<ObjectTemplate> instance = result->InstanceTemplate();
    instance->SetInternalFieldCount(1);
    Handle<ObjectTemplate> prototype = result->PrototypeTemplate();
    prototype->Set(String::New("close"), FunctionTemplate::New(Close));
    prototype->Set(String::New("put"), FunctionTemplate::New(Put));
    prototype->Set(String::New("get"), FunctionTemplate::New(Get));
    return handle_scope.Close(result);
}

}
