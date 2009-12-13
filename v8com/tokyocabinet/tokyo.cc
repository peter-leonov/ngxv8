#include <tcutil.h>
#include <tctdb.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include "tokyo.h"

using namespace std;
using namespace v8;

namespace tc {
namespace util {
namespace tclist {

static Handle<Value> New(const Arguments& args)
{
    HandleScope scope;
    Local<External> list_ptr;
    if (args[0]->IsExternal()) {
        list_ptr = Local<External>::Cast(args[0]);
    } else {
        TCLIST *list = tclistnew();
        list_ptr = External::New(list);
    }
    Local<Object> self = args.This();
    self->SetInternalField(0, list_ptr);
    return scope.Close(self);
}

static Handle<Value> Push(const Arguments& args)
{
    HandleScope scope;
    Local<Value> field = args.This()->GetInternalField(0);
    TCLIST *list = static_cast<TCLIST *>(Local<External>::Cast(field)->Value());
    String::Utf8Value value(args[0]);
    tclistpush2(list, *value);
    return scope.Close(True());
}

static Handle<Value> PushList(const Arguments& args)
{
    HandleScope scope;
    Local<Value> field = Local<Object>::Cast(args[0])->GetInternalField(0);
    TCLIST *l = static_cast<TCLIST *>(Local<External>::Cast(field)->Value());

    field = args.This()->GetInternalField(0);
    TCLIST *list = static_cast<TCLIST *>(Local<External>::Cast(field)->Value());
    tclistpushlist(list, l);
    return scope.Close(True());
}

static Handle<Value> PushMap(const Arguments& args)
{
    HandleScope scope;
    Local<Value> field = Local<Object>::Cast(args[0])->GetInternalField(0);
    TCMAP *map = static_cast<TCMAP *>(Local<External>::Cast(field)->Value());

    field = args.This()->GetInternalField(0);
    TCLIST *list = static_cast<TCLIST *>(Local<External>::Cast(field)->Value());
    tclistpushmap(list, map);
    return scope.Close(True());
}

static Handle<Value> Dispose(const Arguments& args)
{
    HandleScope scope;
    Local<Value> field = args.This()->GetInternalField(0);
    TCLIST *list = static_cast<TCLIST *>(Local<External>::Cast(field)->Value());
    tclistdel(list);
    //printf("tclist deleted\n");
    return scope.Close(True());
}

/*static Handle<Value> Dump(const Arguments& args)
{
    HandleScope scope;
    Local<Value> field = args.This()->GetInternalField(0);
    TCLIST *list = static_cast<TCLIST *>(Local<External>::Cast(field)->Value());
    int len, ksiz;
    const char *kbuf;
    len = tclistnum(list);
    for (int i = 0; i < len; i++) {
        kbuf = static_cast<const char *>(tclistval(list, i, &ksiz));
        printf("%s\n", kbuf);
    }
    return scope.Close(True());
}*/

}

namespace tcmap {

Persistent<ObjectTemplate> __template__;

/*static Handle<Value> Get(Local<String> name, const AccessorInfo &info)
{
    HandleScope scope;
    Local<Value> field = info.Holder()->GetInternalField(0);
    TCMAP *map = static_cast<TCMAP *>(Local<External>::Cast(field)->Value());
    String::Utf8Value key(name);
    const char *v = tcmapget2(map, *key);
    return String::New(v);
    return String::New("");
}

static Handle<Value> __Set__(Local<String> name, Local<Value> value, const AccessorInfo &info)
{
    HandleScope scope;
    Local<Value> o = Local<Object>::Cast(info.Holder()->GetInternalField(0));
}*/

static Handle<Value> New(const Arguments& args)
{
    HandleScope scope;
    TCMAP *map = tcmapnew();
    Local<External> map_ptr = External::New(map);
    Local<Object> self = args.This();
    self->SetInternalField(0, map_ptr);
    return scope.Close(self);
}

static Handle<Value> Get(const Arguments& args)
{
    HandleScope scope;
    Local<Value> field = args.This()->GetInternalField(0);
    TCMAP *map = static_cast<TCMAP *>(Local<External>::Cast(field)->Value());
    String::Utf8Value key(args[0]);
    const char *v = tcmapget2(map, *key);
    return String::New(v);
}

static Handle<Value> Put(const Arguments& args)
{
    HandleScope scope;
    Local<Value> field = args.This()->GetInternalField(0);
    TCMAP *map = static_cast<TCMAP *>(Local<External>::Cast(field)->Value());
    String::Utf8Value key(args[0]);
    String::Utf8Value value(args[1]);
    tcmapput2(map, *key, *value);
    return scope.Close(True());
}

static Handle<Value> PutList(const Arguments& args)
{
    HandleScope scope;
    String::Utf8Value key(args[0]);
    Local<Value> field = Local<Object>::Cast(args[1])->GetInternalField(0);
    TCLIST *list = static_cast<TCLIST *>(Local<External>::Cast(field)->Value());

    field = args.This()->GetInternalField(0);
    TCMAP *map = static_cast<TCMAP *>(Local<External>::Cast(field)->Value());
    tcmapputlist(map, *key, list);
    return scope.Close(True());
}

static Handle<Value> PutMap(const Arguments& args)
{
    HandleScope scope;
    String::Utf8Value key(args[0]);
    Local<Value> field = Local<Object>::Cast(args[1])->GetInternalField(0);
    TCMAP *m = static_cast<TCMAP *>(Local<External>::Cast(field)->Value());

    field = args.This()->GetInternalField(0);
    TCMAP *map = static_cast<TCMAP *>(Local<External>::Cast(field)->Value());
    tcmapputmap(map, *key, m);
    return scope.Close(True());
}

static Handle<Value> Dispose(const Arguments& args)
{
    HandleScope scope;
    Local<Value> field = args.This()->GetInternalField(0);
    TCMAP *map = static_cast<TCMAP *>(Local<External>::Cast(field)->Value());
    tcmapdel(map);
    //printf("tcmap deleted\n");
    return scope.Close(True());
}

}

static Handle<Value> Base64Encode(const Arguments& args)
{
    HandleScope scope;
    Handle<Array> in = Handle<Array>::Cast(args[0]);
    int i;
    int length = in->Length();
    char input[length];
    char *buff;

    for (i = 0; i < length; i++) {
        input[i] = static_cast<unsigned char>(in->Get(Number::New(i))->Int32Value());
    }

    buff = tcbaseencode(input, length);
    Handle<String> ret = String::New(buff);
    free(buff);
    return scope.Close(ret);
}

static Handle<Value> UrlEncode(const Arguments& args)
{
    char *encoded;
    HandleScope scope;
    String::Utf8Value src(args[0]);
    encoded = tcurlencode(*src, src.length());
    Local<String> rv = String::New(encoded);
    free(encoded);
    return scope.Close(rv);
}

static Handle<Value> UrlDecode(const Arguments& args)
{
    char *decoded;
    int siz;
    HandleScope scope;
    String::Utf8Value src(args[0]);
    decoded = tcurldecode(*src, &siz);
    //Local<String> rv = String::New(decoded, siz);
    Local<String> rv = String::New(decoded);
    free(decoded);
    return scope.Close(rv);
}

static Handle<Value> WwwFormDecode(const Arguments& args)
{
    const char *name;
    TCMAP *map = tcmapnew();
    HandleScope scope;
    String::Utf8Value src(args[0]);
    String::AsciiValue type(args[1]);
    Local<Object> result = Object::New();

    tcwwwformdecode2(*src, src.length(), *type, map);
    tcmapiterinit(map);
    while ((name = tcmapiternext2(map)) != NULL) {
        result->Set(String::New(name), String::New(tcmapget2(map, name)));
    }
    tcmapdel(map);

    return result;
}

} // end namespace util

namespace tdb {

static Handle<Value> New(const Arguments& args)
{
    HandleScope scope;
    TCTDB *tdb = tctdbnew();
    tctdbsetmutex(tdb);
    Local<External> tdb_ptr = External::New(tdb);
    Local<Object> self = args.This();
    self->SetInternalField(0, tdb_ptr);
    //Persistent<Object> holder = Persistent<Object>::New(self);
    //holder.MakeWeak(tdb, Dispose);
    return scope.Close(self);
}

static Handle<Value> Open(const Arguments& args)
{
    HandleScope scope;
    String::Utf8Value path(args[0]);
    int32_t omode = args[1]->Int32Value();
    Local<Value> field = args.This()->GetInternalField(0);
    TCTDB *tdb = reinterpret_cast<TCTDB *>(Local<External>::Cast(field)->Value());
    bool rv = tctdbopen(tdb, *path, omode);
    return rv ? True() : False();
}

static Handle<Value> Get(const Arguments& args)
{
    if (!args[0]->IsString() && !args[0]->IsNumber()) {
        return Undefined();
    }

    HandleScope scope;
    String::Utf8Value pkey(args[0]);
    Local<Value> field = args.This()->GetInternalField(0);
    TCTDB *tdb = reinterpret_cast<TCTDB *>(Handle<External>::Cast(field)->Value());
    TCMAP *cols = tctdbget(tdb, *pkey, pkey.length());
    const char *name;
    Local<Object> map = Object::New();
    if (cols) {
        tcmapiterinit(cols);
        while ((name = tcmapiternext2(cols)) != NULL) {
            map->Set(String::New(name), String::New(tcmapget2(cols, name)));
        }
        tcmapdel(cols);
    }
    return scope.Close(map);
}

static Handle<Value> Put(const Arguments& args)
{
    HandleScope scope;
    String::Utf8Value pkey(args[0]);
    Local<Object> cols = Local<Object>::Cast(args[1]);
    Local<Array> names = cols->GetPropertyNames();
    Local<Value> retv;
    TCMAP *map;
    unsigned int i;
    bool putres;

    map = tcmapnew();

    for (i = 0; i < names->Length(); i++) {
        Handle<Value> key = names->Get(Integer::New(i));
        Handle<Value> value =  cols->Get(key);
        tcmapput2(map, *String::Utf8Value(key), *String::Utf8Value(value));
    }

    Handle<Value> field = args.This()->GetInternalField(0);
    TCTDB *tdb = reinterpret_cast<TCTDB *>(Handle<External>::Cast(field)->Value());

    if (args[0]->IsNull()) {
        char pkbuf[256];
        int pksiz;
        pksiz = sprintf(pkbuf, "%ld", static_cast<long>(tctdbgenuid(tdb)));
        putres = tctdbput(tdb, pkbuf, pksiz, map);
        retv = String::New(pkbuf, pksiz);
    } else {
        putres = tctdbput(tdb, *pkey, pkey.length(), map);
        retv = args[0];
    }
    tcmapdel(map);

    if (!putres) {
        return Undefined();
    }

    return retv;
}

static Handle<Value> Close(const Arguments& args)
{
    HandleScope scope;
    Handle<Value> field = args.This()->GetInternalField(0);
    TCTDB *tdb = reinterpret_cast<TCTDB *>(Handle<External>::Cast(field)->Value());
    tctdbclose(tdb);
    //printf("tdb close\n");
    return True();
}

/*static void Dispose(Persistent<Value> handle, void *parameter)
{
    TCTDB *tdb = static_cast<TCTDB *>(parameter);
    tctdbdel(tdb);
    handle.Dispose();
    cout << "Object removed" << endl;
}*/
static Handle<Value> Dispose(const Arguments& args)
{
    HandleScope scope;
    Handle<Value> field = args.This()->GetInternalField(0);
    TCTDB *tdb = reinterpret_cast<TCTDB *>(Handle<External>::Cast(field)->Value());
    tctdbdel(tdb);
    //printf("tdb dispose\n");
    return True();
}

} // end namespace tdb

namespace tdbqry {

typedef struct {
    Local<Function> fun;
} function_t;

int ProcCallback(const void *pkbuf, int pksiz, TCMAP *cols, void *op)
{
    HandleScope scope;
    Local<Object> map = tc::util::tcmap::__template__->NewInstance();
    map->SetInternalField(0, External::New(cols));
    function_t *f = static_cast<function_t *>(op);
    Local<Object> global = Context::GetCurrent()->Global();
    Local<Value> argv[2] = { String::New(static_cast<const char *>(pkbuf)), map };
    Local<Value> rv = f->fun->Call(global, 2, argv);
    return rv->Int32Value();
}

static Handle<Value> New(const Arguments& args)
{
    HandleScope scope;
    Handle<Value> field = Handle<Object>::Cast(args[0])->GetInternalField(0);
    TCTDB *tdb = reinterpret_cast<TCTDB *>(Handle<External>::Cast(field)->Value());
    TDBQRY *qry = tctdbqrynew(tdb);
    Handle<External> qry_ptr = External::New(qry);
    Handle<External> tdb_ptr = External::New(tdb);
    Handle<Object> self = args.This();
    self->SetInternalField(0, qry_ptr);
    self->SetInternalField(1, tdb_ptr);
    return scope.Close(self);
}

static Handle<Value> AddCond(const Arguments& args)
{
    HandleScope scope;
    Handle<Value> field = args.This()->GetInternalField(0);
    TDBQRY *qry = reinterpret_cast<TDBQRY *>(Handle<External>::Cast(field)->Value());
    String::Utf8Value name(args[0]);
    String::Utf8Value expr(args[2]);
    int32_t op = args[1]->Int32Value();
    //printf("%s,%d,%s,%d\n", *name, op, *expr, TDBQCSTROR);
    tctdbqryaddcond(qry, *name, op, *expr);
    return args.This();
}

static Handle<Value> Proc(const Arguments& args)
{
    HandleScope scope;
    Local<Object> o = Local<Object>::Cast(args[0]);
    Local<Function> fun = Local<Function>::Cast(o);
    Local<Value> field = args.This()->GetInternalField(0);
    TDBQRY *qry = reinterpret_cast<TDBQRY *>(Handle<External>::Cast(field)->Value());
    function_t f;
    f.fun = fun;
    tctdbqryproc(qry, ProcCallback, &f);
    return True();
}

static Handle<Value> SearchOut(const Arguments& args)
{
    HandleScope scope;
    Local<Value> field = args.This()->GetInternalField(0);
    TDBQRY *qry = reinterpret_cast<TDBQRY *>(Handle<External>::Cast(field)->Value());
    tctdbqrysearchout(qry);
    return True();
}

static Handle<Value> Search(const Arguments& args)
{
    HandleScope scope;
    Handle<Value> field = args.This()->GetInternalField(0);
    TDBQRY *qry = reinterpret_cast<TDBQRY *>(Handle<External>::Cast(field)->Value());
    field = args.This()->GetInternalField(1);
    TCTDB *tdb = reinterpret_cast<TCTDB *>(Handle<External>::Cast(field)->Value());
    TCLIST *tkeys = tctdbqrysearch(qry);
    int length = tclistnum(tkeys);
    Handle<Array> result = Array::New(length);
    Handle<Object> map;
    TCMAP *cols;
    const char *kbuf, *name;
    int ksiz;

    for(int i = 0; i < length; i++){
        kbuf = static_cast<const char *>(tclistval(tkeys, i, &ksiz));
        //printf("->%s<-%d\n", kbuf, ksiz);
        cols = tctdbget(tdb, kbuf, ksiz);
        if (cols) {
            map = Object::New();
            tcmapiterinit(cols);
            //map->Set(String::New("Id"), String::New(kbuf, ksiz));
            map->Set(String::New("Id"), String::New(kbuf));
            while ((name = tcmapiternext2(cols)) != NULL) {
                map->Set(String::New(name), String::New(tcmapget2(cols, name)));
            }
            tcmapdel(cols);
        }
        result->Set(Integer::New(i), map);
    }
    tclistdel(tkeys);
    return scope.Close(result);
}

static Handle<Value> SetLimit(const Arguments& args)
{
    HandleScope scope;
    Handle<Value> field = args.This()->GetInternalField(0);
    TDBQRY *qry = reinterpret_cast<TDBQRY *>(Handle<External>::Cast(field)->Value());
    int32_t max = args[0]->Int32Value();
    int32_t skip = args[1]->Int32Value();
    tctdbqrysetlimit(qry, max, skip);
    return args.This();
}

static Handle<Value> SetOrder(const Arguments& args)
{
    HandleScope scope;
    Handle<Value> field = args.This()->GetInternalField(0);
    TDBQRY *qry = reinterpret_cast<TDBQRY *>(Handle<External>::Cast(field)->Value());
    String::Utf8Value name(args[0]);
    int32_t type = args[1]->Int32Value();
    tctdbqrysetorder(qry, *name, type);
    return args.This();
}

static Handle<Value> MetaSearch(const Arguments& args)
{
    HandleScope scope;
    Local<Array> others = Local<Array>::Cast(args[0]);
    int num_qrys = others->Length();
    int32_t type = args[1]->Int32Value();

    Local<Value> field = args.This()->GetInternalField(0);
    TDBQRY *qry = static_cast<TDBQRY *>(Local<External>::Cast(field)->Value());

    TDBQRY* qrys[num_qrys+1];

    qrys[0] = qry;

    for (int i = 0; i < num_qrys; i++) {
        Local<Value> x = Local<Object>::Cast(others->Get(Integer::New(i)))->GetInternalField(0);
        qrys[i+1] = static_cast<TDBQRY *>(Local<External>::Cast(x)->Value());
    }

    field = args.This()->GetInternalField(1);
    TCTDB *tdb = static_cast<TCTDB *>(Local<External>::Cast(field)->Value());
    TCLIST *keys = tctdbmetasearch(qrys, num_qrys+1, type);
    int length, ksiz;
    const char *kbuf, *name;
    TCMAP *cols;
    length = tclistnum(keys);

    Local<Array> result = Array::New(length);
    Local<Object> map;

    for (int i = 0; i < length; i++) {
        kbuf = static_cast<const char *>(tclistval(keys, i, &ksiz));
        cols = tctdbget(tdb, kbuf, ksiz);
        if (cols) {
            map = Object::New();
            tcmapiterinit(cols);
            //map->Set(String::New("Id"), String::New(kbuf, ksiz));
            map->Set(String::New("Id"), String::New(kbuf));
            while ((name = tcmapiternext2(cols)) != NULL) {
                map->Set(String::New(name), String::New(tcmapget2(cols, name)));
            }
            tcmapdel(cols);
        }
        result->Set(Integer::New(i), map);
    }
    tclistdel(keys);
    return scope.Close(result);
}

static Handle<Value> Dispose(const Arguments& args)
{
    HandleScope scope;
    Handle<Value> field = args.This()->GetInternalField(0);
    TDBQRY *qry = reinterpret_cast<TDBQRY *>(Handle<External>::Cast(field)->Value());
    tctdbqrydel(qry);
    //printf("tdbqry dispose\n");
    return True();
}

} // end namespace tdbqry

namespace tmpl {

static Handle<Value> New(const Arguments& args)
{
    HandleScope scope;
    TCTMPL *tmpl = tctmplnew();
    Local<External> tmpl_ptr = External::New(tmpl);
    Local<Object> self = args.This();
    self->SetInternalField(0, tmpl_ptr);
    return scope.Close(self);
}

static Handle<Value> GetConf(const Arguments& args)
{
    HandleScope scope;
    String::AsciiValue name(args[0]);
    Local<Value> field = args.This()->GetInternalField(0);
    TCTMPL *tmpl = reinterpret_cast<TCTMPL *>(Local<External>::Cast(field)->Value());
    const char *value = tctmplconf(tmpl, *name);
    return scope.Close(String::New(value));
}

static Handle<Value> Load(const Arguments& args)
{
    HandleScope scope;
    String::Utf8Value path(args[0]);
    Local<Value> field = args.This()->GetInternalField(0);
    TCTMPL *tmpl = reinterpret_cast<TCTMPL *>(Local<External>::Cast(field)->Value());
    tctmplload2(tmpl, *path);
    return scope.Close(True());
}

static Handle<Value> Dump(const Arguments& args)
{
    HandleScope scope;
    /*Local<Object> object = Local<Object>::Cast(args[0]);
    Local<Array> names = object->GetPropertyNames();
    TCMAP *vars = tcmapnew();
    int i = 0;
    for (i; i < names->Length(); i++) {
        Handle<Value> key = names->Get(Integer::New(i));
        Handle<Value> value = object->Get(key);
        if (value->IsObject()) {
        } else if (value->IsArray()) {
        } else if (value->IsString()) {
            tcmapput2(vars, *String::Utf8Value(key), *String::Utf8Value(value));
        }
    }*/
    Local<Value> field = Local<Object>::Cast(args[0])->GetInternalField(0);
    TCMAP *vars = static_cast<TCMAP *>(Local<External>::Cast(field)->Value());
    field = args.This()->GetInternalField(0);
    TCTMPL *tmpl = static_cast<TCTMPL *>(Local<External>::Cast(field)->Value());
    char *str = tctmpldump(tmpl, vars);
    Local<String> result = String::New(str);
    tcfree(str);
    //tcmapdel(vars);
    return scope.Close(result);
}

static Handle<Value> Dispose(const Arguments& args)
{
    HandleScope scope;
    Local<Value> field = args.This()->GetInternalField(0);
    TCTMPL *tmpl = reinterpret_cast<TCTMPL *>(Local<External>::Cast(field)->Value());
    tctmpldel(tmpl);
    //printf("tctmpl deleted\n");
    return scope.Close(True());
}

} // end namespace tmpl

} // end namespace tc

extern "C" {
    
Handle<ObjectTemplate> createObject()
{
    HandleScope handle_scope;
    Handle<ObjectTemplate> tc = ObjectTemplate::New();

    Handle<FunctionTemplate> tdb = FunctionTemplate::New(tc::tdb::New);
    tdb->SetClassName(String::New("TDB"));
    tdb->Set(String::New("OWRITER"), Integer::New(TDBOWRITER));
    tdb->Set(String::New("OREADER"), Integer::New(TDBOREADER));
    tdb->Set(String::New("OCREAT"), Integer::New(TDBOCREAT));
    tdb->Set(String::New("QPOUT"), Integer::New(TDBQPOUT));
    tdb->Set(String::New("QPPUT"), Integer::New(TDBQPPUT));
    tdb->Set(String::New("QPSTOP"), Integer::New(TDBQPSTOP));
    Handle<ObjectTemplate> tdbInstance = tdb->InstanceTemplate();
    tdbInstance->SetInternalFieldCount(1);
    Handle<ObjectTemplate> tdbPrototype = tdb->PrototypeTemplate();
    tdbPrototype->Set(String::New("open"), FunctionTemplate::New(tc::tdb::Open));
    tdbPrototype->Set(String::New("close"), FunctionTemplate::New(tc::tdb::Close));
    tdbPrototype->Set(String::New("get"), FunctionTemplate::New(tc::tdb::Get));
    tdbPrototype->Set(String::New("put"), FunctionTemplate::New(tc::tdb::Put));
    tdbPrototype->Set(String::New("dispose"), FunctionTemplate::New(tc::tdb::Dispose));
    //tdbPrototype->Set(String::New("search"), FunctionTemplate::New(tc::tdb::Search));
    tc->Set(String::New("TDB"), tdb);

    Handle<FunctionTemplate> tdbqry = FunctionTemplate::New(tc::tdbqry::New);
    tdbqry->SetClassName(String::New("TDBQRY"));
    tdbqry->Set(String::New("QCSTREQ"), Integer::New(TDBQCSTREQ));
    tdbqry->Set(String::New("QCSTRINC"), Integer::New(TDBQCSTRINC));
    tdbqry->Set(String::New("QCSTRBW"), Integer::New(TDBQCSTRBW));
    tdbqry->Set(String::New("QCSTREW"), Integer::New(TDBQCSTREW));
    tdbqry->Set(String::New("QCSTRAND"), Integer::New(TDBQCSTRAND));
    tdbqry->Set(String::New("QCSTROR"), Integer::New(TDBQCSTROR));
    tdbqry->Set(String::New("QCSTROREQ"), Integer::New(TDBQCSTROREQ));
    tdbqry->Set(String::New("QCSTRRX"), Integer::New(TDBQCSTRRX));
    tdbqry->Set(String::New("QCNUMEQ"), Integer::New(TDBQCNUMEQ));
    tdbqry->Set(String::New("QCNUMGE"), Integer::New(TDBQCNUMGE));
    tdbqry->Set(String::New("QCNUMGT"), Integer::New(TDBQCNUMGT));
    tdbqry->Set(String::New("QCNUMLE"), Integer::New(TDBQCNUMLE));
    tdbqry->Set(String::New("QCNUMLT"), Integer::New(TDBQCNUMLT));
    tdbqry->Set(String::New("QOSTRASC"), Integer::New(TDBQOSTRASC));
    tdbqry->Set(String::New("QOSTRDESC"), Integer::New(TDBQOSTRDESC));
    tdbqry->Set(String::New("QONUMASC"), Integer::New(TDBQONUMASC));
    tdbqry->Set(String::New("QONUMDESC"), Integer::New(TDBQONUMDESC));
    tdbqry->Set(String::New("MSUNION"), Integer::New(TDBMSUNION));
    Handle<ObjectTemplate> qryInstance = tdbqry->InstanceTemplate();
    qryInstance->SetInternalFieldCount(2);
    Handle<ObjectTemplate> qryPrototype = tdbqry->PrototypeTemplate();
    qryPrototype->Set(String::New("addcond"), FunctionTemplate::New(tc::tdbqry::AddCond));
    qryPrototype->Set(String::New("proc"), FunctionTemplate::New(tc::tdbqry::Proc));
    qryPrototype->Set(String::New("searchout"), FunctionTemplate::New(tc::tdbqry::SearchOut));
    qryPrototype->Set(String::New("search"), FunctionTemplate::New(tc::tdbqry::Search));
    qryPrototype->Set(String::New("setlimit"), FunctionTemplate::New(tc::tdbqry::SetLimit));
    qryPrototype->Set(String::New("setorder"), FunctionTemplate::New(tc::tdbqry::SetOrder));
    qryPrototype->Set(String::New("metasearch"), FunctionTemplate::New(tc::tdbqry::MetaSearch));
    qryPrototype->Set(String::New("dispose"), FunctionTemplate::New(tc::tdbqry::Dispose));
    tc->Set(String::New("TDBQRY"), tdbqry);

    Local<FunctionTemplate> tmpl = FunctionTemplate::New(tc::tmpl::New);
    tmpl->SetClassName(String::New("TMPL"));
    Local<ObjectTemplate> tmplInstance = tmpl->InstanceTemplate();
    tmplInstance->SetInternalFieldCount(1);
    Local<ObjectTemplate> tmplPrototype = tmpl->PrototypeTemplate();
    tmplPrototype->Set(String::New("conf"), FunctionTemplate::New(tc::tmpl::GetConf));
    tmplPrototype->Set(String::New("load"), FunctionTemplate::New(tc::tmpl::Load));
    tmplPrototype->Set(String::New("dump"), FunctionTemplate::New(tc::tmpl::Dump));
    tmplPrototype->Set(String::New("dispose"), FunctionTemplate::New(tc::tmpl::Dispose));
    tc->Set(String::New("TMPL"), tmpl);

    Local<ObjectTemplate> util = ObjectTemplate::New();

    Local<FunctionTemplate> tclist = FunctionTemplate::New(tc::util::tclist::New);
    tclist->SetClassName(String::New("TCLIST"));
    Local<ObjectTemplate> tclistInstance = tclist->InstanceTemplate();
    tclistInstance->SetInternalFieldCount(1);
    Local<ObjectTemplate> tclistPrototype = tclist->PrototypeTemplate();
    tclistPrototype->Set(String::New("push"), FunctionTemplate::New(tc::util::tclist::Push));
    tclistPrototype->Set(String::New("pushList"), FunctionTemplate::New(tc::util::tclist::PushList));
    tclistPrototype->Set(String::New("pushMap"), FunctionTemplate::New(tc::util::tclist::PushMap));
    tclistPrototype->Set(String::New("dispose"), FunctionTemplate::New(tc::util::tclist::Dispose));
    //tclistPrototype->Set(String::New("dump"), FunctionTemplate::New(tc::util::tclist::Dump));

    //Local<FunctionTemplate> tcmap = FunctionTemplate::New(tc::util::tcmap::New);
    Local<FunctionTemplate> tcmap = FunctionTemplate::New(tc::util::tcmap::New);
    tcmap->SetClassName(String::New("TCMAP"));
    Local<ObjectTemplate> tcmapInstance = tcmap->InstanceTemplate();
    tcmapInstance->SetInternalFieldCount(1);
    Local<ObjectTemplate> tcmapPrototype = tcmap->PrototypeTemplate();
    tcmapPrototype->Set(String::New("get"), FunctionTemplate::New(tc::util::tcmap::Get));
    tcmapPrototype->Set(String::New("put"), FunctionTemplate::New(tc::util::tcmap::Put));
    tcmapPrototype->Set(String::New("putList"), FunctionTemplate::New(tc::util::tcmap::PutList));
    tcmapPrototype->Set(String::New("putMap"), FunctionTemplate::New(tc::util::tcmap::PutMap));
    tcmapPrototype->Set(String::New("dispose"), FunctionTemplate::New(tc::util::tcmap::Dispose));
    tc::util::tcmap::__template__ = Persistent<ObjectTemplate>::New(tcmapInstance);

    util->Set(String::New("TCLIST"), tclist);
    util->Set(String::New("TCMAP"), tcmap);
    util->Set(String::New("b64encode"), FunctionTemplate::New(tc::util::Base64Encode));
    util->Set(String::New("urlencode"), FunctionTemplate::New(tc::util::UrlEncode));
    util->Set(String::New("urldecode"), FunctionTemplate::New(tc::util::UrlDecode));
    util->Set(String::New("wwwformdecode"), FunctionTemplate::New(tc::util::WwwFormDecode));
    tc->Set(String::New("util"), util);

    return handle_scope.Close(tc);
}

}
