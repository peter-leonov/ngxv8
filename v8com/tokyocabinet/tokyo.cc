#include <tcutil.h>
#include <tctdb.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include "tokyo.h"

#include <iostream>

using namespace std;
using namespace v8;

static void dump_map(TCMAP *m)
{
    const char *k;
    tcmapiterinit(m);
    while ((k = tcmapiternext2(m)) != NULL) {
        printf("1\n");
    }
}

namespace tc {
namespace util {
namespace tclist {

static Handle<Value> Initialize(const Arguments& args)
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
    return scope.Close(True());
}

static Handle<Value> Dump(const Arguments& args)
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
}

}

namespace tcmap {

static Handle<Value> Initialize(const Arguments& args)
{
    HandleScope scope;
    TCMAP *map = tcmapnew();
    Local<External> map_ptr = External::New(map);
    Local<Object> self = args.This();
    self->SetInternalField(0, map_ptr);
    return scope.Close(self);
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

static Handle<Value> Dispose(const Arguments& args)
{
    HandleScope scope;
    Local<Value> field = args.This()->GetInternalField(0);
    TCMAP *map = static_cast<TCMAP *>(Local<External>::Cast(field)->Value());
    tcmapdel(map);
    return scope.Close(True());
}

}

static Handle<Value> Base64Encode(const Arguments& args)
{
    HandleScope scope;
    Handle<Array> in = Handle<Array>::Cast(args[0]);
    int length = in->Length();
    int i = 0;
    char input[length];
    char *buff;

    for (i; i < length; i++) {
        input[i] = static_cast<unsigned char>(in->Get(Number::New(i))->Int32Value());
    }

    buff = tcbaseencode(input, length);
    Handle<String> ret = String::New(buff);
    free(buff);
    return scope.Close(ret);
}

} // end namespace util

namespace tdb {

static Handle<Value> Initialize(const Arguments& args)
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

static Handle<Value> Put(const Arguments& args)
{
    HandleScope scope;
    String::Utf8Value pkey(args[0]);
    Handle<Object> cols = Handle<Object>::Cast(args[1]);
    Handle<Array> names = cols->GetPropertyNames();
    TCMAP *map = tcmapnew();
    int i = 0;
    for (i; i < names->Length(); i++) {
        Handle<Value> key = names->Get(Integer::New(i));
        Handle<Value> value =  cols->Get(key);
        tcmapput2(map, *String::Utf8Value(key), *String::Utf8Value(value));
    }
    Handle<Value> field = args.This()->GetInternalField(0);
    TCTDB *tdb = reinterpret_cast<TCTDB *>(Handle<External>::Cast(field)->Value());
    if (!tctdbput(tdb, *pkey, sizeof(*pkey), map)) {
        tcmapdel(map);
        return False();
    }
    tcmapdel(map);
    return True();
}
/*
static Handle<Value> Search(const Arguments& args)
{
    HandleScope scope;
    Handle<Value> field = args.This()->GetInternalField(0);
    TCTDB *tdb = reinterpret_cast<TCTDB *>(Handle<External>::Cast(field)->Value());
    int i, rsiz;
    const char *rbuf, *name;
    TCMAP *cols;
    TDBQRY *qry;
    TCLIST *res;
    Handle<ObjectTemplate> resultTeml = ObjectTemplate::New();
    Handle<Object> result = resultTeml->NewInstance();
    qry = tctdbqrynew(tdb);
    tctdbqryaddcond(qry, "pubstart", TDBQCNUMLE, "1252774800");
    tctdbqryaddcond(qry, "pubend", TDBQCNUMGE, "1252774800");
    tctdbqryaddcond(qry, "type", TDBQCSTREQ, "CoverInterviewArticle");
    tctdbqrysetorder(qry, "pubstart", TDBQONUMDESC);
    tctdbqrysetmax(qry, 1);
    res = tctdbqrysearch(qry);
    for (i = 0; i < tclistnum(res); i++) {
        rbuf = static_cast<const char *>(tclistval(res, i, &rsiz));
        cols = tctdbget(tdb, rbuf, rsiz);
        if (cols) {
            tcmapiterinit(cols);
            while ((name = tcmapiternext2(cols)) != NULL) {
                Handle<String> key = String::New(name);
                Handle<String> value = String::New(tcmapget2(cols, name));
                result->Set(key, value);
            }
            tcmapdel(cols);
        }
    }
    tclistdel(res);
    tctdbqrydel(qry);
    return scope.Close(result);
}
*/

static Handle<Value> Close(const Arguments& args)
{
    HandleScope scope;
    Handle<Value> field = args.This()->GetInternalField(0);
    TCTDB *tdb = reinterpret_cast<TCTDB *>(Handle<External>::Cast(field)->Value());
    tctdbclose(tdb);
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
    return True();
}

} // end namespace tdb

namespace tdbqry {

static Handle<Value> Initialize(const Arguments& args)
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
    Handle<Object> map;// = Object::New();
    TCMAP *cols;
    const char *kbuf, *name;
    int ksiz;

    for(int i = 0; i < length; i++){
        kbuf = static_cast<const char *>(tclistval(tkeys, i, &ksiz));
        cols = tctdbget(tdb, kbuf, ksiz);
        if (cols) {
            map = Object::New();
            tcmapiterinit(cols);
            while ((name = tcmapiternext2(cols)) != NULL) {
                map->Set(String::New(name), String::New(tcmapget2(cols, name)));
            }
            tcmapdel(cols);
        }
        //result->Set(Integer::New(i), String::New(kbuf));
        result->Set(Integer::New(i), map);
    }
    tclistdel(tkeys);
    return scope.Close(result);
    /*Handle<Value> argv[1] = { External::New(tkeys) };
    Local<Object> global = Context::GetCurrent()->Global();
    Local<Object> components = Local<Object>::Cast(global->Get(String::New("Components")));
    Local<Object> classes = Local<Object>::Cast(components->Get(String::New("classes")));
    Local<Object> tc = Local<Object>::Cast(classes->Get(getName()));
    Local<Object> util = Local<Object>::Cast(tc->Get(String::New("util")));
    Local<Function> tclist = Local<Function>::Cast(util->Get(String::New("TCLIST")));
    Local<Object> list = tclist->NewInstance(1, argv);
    tclistdel(tkeys);
    return scope.Close(list);*/
}

static Handle<Value> SetLimit(const Arguments& args)
{
    HandleScope scope;
    Handle<Value> field = args.This()->GetInternalField(0);
    TDBQRY *qry = reinterpret_cast<TDBQRY *>(Handle<External>::Cast(field)->Value());
    int32_t max = args[0]->Int32Value();
    int32_t skip = args[1]->Int32Value();
    tctdbqrysetlimit(qry, max, skip);
}

static Handle<Value> SetOrder(const Arguments& args)
{
    HandleScope scope;
    Handle<Value> field = args.This()->GetInternalField(0);
    TDBQRY *qry = reinterpret_cast<TDBQRY *>(Handle<External>::Cast(field)->Value());
    String::Utf8Value name(args[0]);
    int32_t type = args[1]->Int32Value();
    tctdbqrysetorder(qry, *name, type);
    return True();
}

static Handle<Value> Dispose(const Arguments& args)
{
    HandleScope scope;
    Handle<Value> field = args.This()->GetInternalField(0);
    TDBQRY *qry = reinterpret_cast<TDBQRY *>(Handle<External>::Cast(field)->Value());
    tctdbqrydel(qry);
    return True();
}

} // end namespace tdbqry

namespace tmpl {

static Handle<Value> Initialize(const Arguments& args)
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
    return scope.Close(True());
}

} // end namespace tmpl

} // end namespace tc

extern "C" {
    
Handle<String> getName()
{
    HandleScope scope;
    Handle<String> name = String::New("@v8com/tokyocabinet;1");
    return scope.Close(name);
}

Handle<ObjectTemplate> createObject()
{
    HandleScope handle_scope;
    Handle<ObjectTemplate> tc = ObjectTemplate::New();

    Handle<FunctionTemplate> tdb = FunctionTemplate::New(tc::tdb::Initialize);
    tdb->SetClassName(String::New("TDB"));
    tdb->Set(String::New("OWRITER"), Integer::New(TDBOWRITER));
    tdb->Set(String::New("OREADER"), Integer::New(TDBOREADER));
    tdb->Set(String::New("OCREAT"), Integer::New(TDBOCREAT));
    Handle<ObjectTemplate> tdbInstance = tdb->InstanceTemplate();
    tdbInstance->SetInternalFieldCount(1);
    Handle<ObjectTemplate> tdbPrototype = tdb->PrototypeTemplate();
    tdbPrototype->Set(String::New("open"), FunctionTemplate::New(tc::tdb::Open));
    tdbPrototype->Set(String::New("close"), FunctionTemplate::New(tc::tdb::Close));
    tdbPrototype->Set(String::New("put"), FunctionTemplate::New(tc::tdb::Put));
    tdbPrototype->Set(String::New("dispose"), FunctionTemplate::New(tc::tdb::Dispose));
    //tdbPrototype->Set(String::New("search"), FunctionTemplate::New(tc::tdb::Search));
    tc->Set(String::New("TDB"), tdb);

    Handle<FunctionTemplate> tdbqry = FunctionTemplate::New(tc::tdbqry::Initialize);
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
    tdbqry->Set(String::New("QONUMASC"), Integer::New(TDBQONUMASC));
    tdbqry->Set(String::New("QONUMDESC"), Integer::New(TDBQONUMDESC));
    Handle<ObjectTemplate> qryInstance = tdbqry->InstanceTemplate();
    qryInstance->SetInternalFieldCount(2);
    Handle<ObjectTemplate> qryPrototype = tdbqry->PrototypeTemplate();
    qryPrototype->Set(String::New("addcond"), FunctionTemplate::New(tc::tdbqry::AddCond));
    qryPrototype->Set(String::New("search"), FunctionTemplate::New(tc::tdbqry::Search));
    qryPrototype->Set(String::New("setlimit"), FunctionTemplate::New(tc::tdbqry::SetLimit));
    qryPrototype->Set(String::New("setorder"), FunctionTemplate::New(tc::tdbqry::SetOrder));
    qryPrototype->Set(String::New("dispose"), FunctionTemplate::New(tc::tdbqry::Dispose));
    tc->Set(String::New("TDBQRY"), tdbqry);

    Local<FunctionTemplate> tmpl = FunctionTemplate::New(tc::tmpl::Initialize);
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

    Local<FunctionTemplate> tclist = FunctionTemplate::New(tc::util::tclist::Initialize);
    tclist->SetClassName(String::New("TCLIST"));
    Local<ObjectTemplate> tclistInstance = tclist->InstanceTemplate();
    tclistInstance->SetInternalFieldCount(1);
    Local<ObjectTemplate> tclistPrototype = tclist->PrototypeTemplate();
    tclistPrototype->Set(String::New("pushMap"), FunctionTemplate::New(tc::util::tclist::PushMap));
    tclistPrototype->Set(String::New("dispose"), FunctionTemplate::New(tc::util::tclist::Dispose));
    tclistPrototype->Set(String::New("dump"), FunctionTemplate::New(tc::util::tclist::Dump));

    Local<FunctionTemplate> tcmap = FunctionTemplate::New(tc::util::tcmap::Initialize);
    tcmap->SetClassName(String::New("TCMAP"));
    Local<ObjectTemplate> tcmapInstance = tcmap->InstanceTemplate();
    tcmapInstance->SetInternalFieldCount(1);
    Local<ObjectTemplate> tcmapPrototype = tcmap->PrototypeTemplate();
    tcmapPrototype->Set(String::New("put"), FunctionTemplate::New(tc::util::tcmap::Put));
    tcmapPrototype->Set(String::New("putList"), FunctionTemplate::New(tc::util::tcmap::PutList));
    tcmapPrototype->Set(String::New("dispose"), FunctionTemplate::New(tc::util::tcmap::Dispose));

    util->Set(String::New("TCLIST"), tclist);
    util->Set(String::New("TCMAP"), tcmap);
    util->Set(String::New("b64encode"), FunctionTemplate::New(tc::util::Base64Encode));
    tc->Set(String::New("util"), util);

    return handle_scope.Close(tc);
}

}
