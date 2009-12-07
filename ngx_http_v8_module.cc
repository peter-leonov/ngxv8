extern "C" {
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <nginx.h>

#include <sys/mman.h>
#include <fcntl.h>
#include <dlfcn.h>
}
#include <v8.h>
#include <v8-debug.h>
//#include <../src/v8.h>
//#include <iostream>

using namespace std;
using namespace v8;

extern ngx_module_t  ngx_http_v8_module;

static char *ngx_http_v8(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_v8com(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void *ngx_http_v8_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_v8_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_v8_init_process(ngx_cycle_t *cycle);
static Handle<Value> Log(const Arguments& args);
static Handle<Value> BindPool(const Arguments& args);
static Handle<Value> ReadBody(const Arguments& args);
static Handle<Value> Write(const Arguments& args);
static Handle<Value> AddResponseHeader(const Arguments& args);
static void *Unwrap(Handle<Object> obj, int field);

typedef struct {
    Persistent<Function> fun;
} function_t;

typedef struct {
    Persistent<Object> recv;
    Persistent<Function> fun;
} method_t;

typedef struct {
    ngx_chain_t *head;
    ngx_chain_t *last;
    size_t size;
} brigade_t;

typedef struct {
    Persistent<Context> context;
    Persistent<Function> process;
    Persistent<ObjectTemplate> classes;
    Persistent<ObjectTemplate> interfaces;
    Persistent<ObjectTemplate> request_tmpl;
    Persistent<ObjectTemplate> response_tmpl;
} ngx_http_v8_loc_conf_t;

typedef struct {
    function_t *next;
    ngx_uint_t done;
} ngx_http_v8_ctx_t;

static ngx_command_t  ngx_http_v8_commands[] = {

    { ngx_string("v8"),
        NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_TAKE1,
        ngx_http_v8,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL },

    { ngx_string("v8com"),
        NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_TAKE2,
        ngx_http_v8com,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL },

    ngx_null_command
};

static ngx_http_module_t ngx_http_v8_module_ctx = {
    NULL,                                /* preconfiguration */
    NULL,                                /* postconfiguration */

    NULL,                                /* create main configuration */
    NULL,                                /* init main configuration */

    NULL,                                /* create server configuration */
    NULL,                                /* merge server configuration */

    ngx_http_v8_create_loc_conf,         /* create location configuration */
    ngx_http_v8_merge_loc_conf           /* merge location configuration */

};

ngx_module_t  ngx_http_v8_module = {
    NGX_MODULE_V1,
    &ngx_http_v8_module_ctx,       /* module context */
    ngx_http_v8_commands,          /* module directives */
    NGX_HTTP_MODULE,               /* module type */
    NULL,                          /* init master */
    NULL,                          /* init module */
    ngx_http_v8_init_process,                          /* init process */
    NULL,                          /* init thread */
    NULL,                          /* exit thread */
    NULL,                          /* exit process */
    NULL,                          /* exit master */
    NGX_MODULE_V1_PADDING
};

ngx_int_t ngx_http_v8_init_process(ngx_cycle_t *cycle)
{
    Debug::EnableAgent("ngxv8", 5858);
    return 0;
}

/*
namespace xhr {

static Handle<Value> Initialize(const Arguments& args)
{
    return True();
}

static Handle<Value> Open(const Arguments& args)
{
    return True();
}

static Handle<Value> Send(const Arguments& args)
{
    return True();
}

} // end namespace xhr
*/

static void HandleDispose(Persistent<Value> handle, void *p)
{
    handle.Dispose();
}

static Handle<Value> GetUri(Local<String> name,
                      const AccessorInfo& info)
{
    ngx_http_request_t *r = static_cast<ngx_http_request_t*>(Unwrap(info.Holder(), 0));
    ngx_str_t uri = r->uri;
    return String::New(reinterpret_cast<const char*>(uri.data), uri.len);
}

static Handle<Value> GetMethod(Local<String> name,
                      const AccessorInfo& info)
{
    ngx_http_request_t *r = static_cast<ngx_http_request_t*>(Unwrap(info.Holder(), 0));
    return String::New(reinterpret_cast<const char*>(r->method_name.data), r->method_name.len);
}

static Handle<Value> GetUserAgent(Local<String> name,
                      const AccessorInfo& info)
{
    ngx_http_request_t *r = static_cast<ngx_http_request_t*>(Unwrap(info.Holder(), 0));
    ngx_str_t agent = r->headers_in.user_agent->value;
    return String::New(reinterpret_cast<const char*>(agent.data), agent.len);

}
static Handle<Value> GetArgs(Local<String> name,
                      const AccessorInfo& info)
{
    ngx_http_request_t *r = static_cast<ngx_http_request_t*>(Unwrap(info.Holder(), 0));
    ngx_str_t args = r->args;
    return String::New(reinterpret_cast<const char*>(args.data), args.len);
}

static Handle<Value> GetBodyBuf(Local<String> name,
                      const AccessorInfo& info)
{
    size_t len;
    ngx_http_request_t *r = static_cast<ngx_http_request_t *>(Unwrap(info.Holder(), 0));
    if (r->request_body == NULL
        || r->request_body->temp_file
        || r->request_body->bufs == NULL) {
        return Undefined();
    }

    len = r->request_body->bufs->buf->last - r->request_body->bufs->buf->pos;

    if (len == 0) {
        return Undefined();
    }

    return String::New(reinterpret_cast<const char *>(r->request_body->bufs->buf->pos), len);
}

static Handle<Value> GetBodyFileOrBuf(Local<String> name,
                      const AccessorInfo& info)
{
    ngx_http_request_t  *r;
    char                *data;
    int                 fd;
    off_t               len;

    r = static_cast<ngx_http_request_t*>(Unwrap(info.Holder(), 0));

    if (r->request_body == NULL
        || r->request_body->temp_file == NULL) {
        return GetBodyBuf(name, info);
    }

    fd = r->request_body->temp_file->file.fd;
    len = r->headers_in.content_length_n;

    data = static_cast<char*>(mmap(NULL, len, PROT_READ, MAP_PRIVATE, fd, 0));

    HandleScope scope;
    Local<String> b = String::New(data, len);
    munmap(data, len);

    return scope.Close(b);
}

static Handle<Value> GetVariable(const Arguments& args)
{
    ngx_http_request_t          *r;
    size_t                      len;
    u_char                      *p, *lowcase;
    ngx_str_t                   var;
    ngx_uint_t                  hash;
    ngx_http_variable_value_t   *vv;

    HandleScope scope;
    String::AsciiValue name(args[0]);
    len = name.length();
    r = static_cast<ngx_http_request_t*>(Unwrap(args.This(), 0));
    lowcase = static_cast<u_char*>(ngx_pnalloc(r->pool, len));
    p = reinterpret_cast<u_char*>(*name);
    hash = ngx_hash_strlow(lowcase, p, len);
    var.len = len;
    var.data = lowcase;
    vv = ngx_http_get_variable(r, &var, hash, 1);

    if (vv->not_found) {
        return Undefined();
    }
    return String::New(reinterpret_cast<const char*>(vv->data), vv->len);
}

static Handle<Value> GetRespContentType(Local<String> name,
                      const AccessorInfo& info)
{
    ngx_http_request_t *r = static_cast<ngx_http_request_t*>(Unwrap(info.Holder(), 0));
    return String::New(reinterpret_cast<const char*>(r->headers_out.content_type.data),
        r->headers_out.content_type.len);
}

void SetRespContentType(Local<String> name,
                      Local<Value> val,
                      const AccessorInfo& info)
{
    ngx_http_request_t *r = static_cast<ngx_http_request_t*>(Unwrap(info.Holder(), 0));
    String::Utf8Value value(val);
    size_t len = value.length();
    u_char *p = static_cast<u_char*>(ngx_pnalloc(r->pool, len));
    ngx_memcpy(p, *value, len);
    r->headers_out.content_type.data = p;
    r->headers_out.content_type.len = len;
}

static Local<ObjectTemplate> MakeRequestTemplate()
{
    HandleScope scope;
    Local<ObjectTemplate> result = ObjectTemplate::New();
    result->SetInternalFieldCount(1);
    result->SetAccessor(String::NewSymbol("uri"), GetUri);
    result->SetAccessor(String::NewSymbol("method"), GetMethod);
    result->SetAccessor(String::NewSymbol("userAgent"), GetUserAgent);
    result->SetAccessor(String::NewSymbol("args"), GetArgs);
    result->SetAccessor(String::NewSymbol("body"), GetBodyFileOrBuf);
    result->Set(String::New("$"), FunctionTemplate::New(GetVariable));
    result->Set(String::New("bind"), FunctionTemplate::New(BindPool));
    result->Set(String::New("readBody"), FunctionTemplate::New(ReadBody));
    return scope.Close(result);
}

static Local<ObjectTemplate> MakeResponseTemplate()
{
    HandleScope scope;
    Local<ObjectTemplate> result = ObjectTemplate::New();
    result->SetInternalFieldCount(2);
    result->Set(String::New("write"), FunctionTemplate::New(Write));
    result->Set(String::New("addHeader"), FunctionTemplate::New(AddResponseHeader));
    result->SetAccessor(String::NewSymbol("contentType"), GetRespContentType, SetRespContentType);
    return scope.Close(result);
}

static Local<Object> WrapRequest(ngx_http_v8_loc_conf_t *v8lcf,
                           ngx_http_request_t *r)
{
    HandleScope scope;
    if (v8lcf->request_tmpl.IsEmpty()) {
        Local<ObjectTemplate> tmpl = MakeRequestTemplate();
        v8lcf->request_tmpl = Persistent<ObjectTemplate>::New(tmpl);
    }
    Local<Object> result = v8lcf->request_tmpl->NewInstance();
    result->SetInternalField(0, External::New(r));
    return scope.Close(result);
}

static Local<Object> WrapResponse(ngx_http_v8_loc_conf_t *v8lcf,
                           ngx_http_request_t *r,
                           brigade_t *b)
{
    HandleScope scope;
    if (v8lcf->response_tmpl.IsEmpty()) {
        Local<ObjectTemplate> tmpl = MakeResponseTemplate();
        v8lcf->response_tmpl = Persistent<ObjectTemplate>::New(tmpl);
    }
    Local<Object> result = v8lcf->response_tmpl->NewInstance();
    result->SetInternalField(0, External::New(r));
    result->SetInternalField(1, External::New(b));
    return scope.Close(result);
}

static void *Unwrap(Handle<Object> obj, int field)
{
    return Handle<External>::Cast(obj->GetInternalField(field))->Value();
}


static
ngx_int_t ngx_http_v8_call_handler(
    ngx_http_request_t *r,
    ngx_http_v8_loc_conf_t *v8lcf,
    Persistent<Function> fun,
    brigade_t *b
) {
    ngx_connection_t *c;

    c = r->connection;

    Context::Scope context_scope(v8lcf->context);
    HandleScope scope;

    Local<Object> request_obj = WrapRequest(v8lcf, r);
    Local<Object> response_obj = WrapResponse(v8lcf, r, b);
    Handle<Value> argv[2] = { request_obj, response_obj };

    TryCatch trycatch;
    Handle<Value> result = fun->Call(v8lcf->context->Global(), 2, argv);
    if (trycatch.HasCaught()) {
        Local<Value> st = trycatch.StackTrace();
        String::AsciiValue st_str(st);
        fprintf(stderr, "call: %s\n", *st_str);
        //cerr << *st_str << endl;
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (c->destroyed) {
        return NGX_DONE;
    }

    if (result->IsUndefined()) {
        return NGX_OK;
    }

    //internal::Heap::CollectAllGarbage(false);
    return static_cast<ngx_int_t>(result->Int32Value());
}

static void
ngx_http_v8_handler_request(ngx_http_request_t *r)
{
    ngx_int_t               rc;
    brigade_t               b;
    ngx_http_v8_ctx_t       *ctx;
    ngx_http_v8_loc_conf_t  *v8lcf;
    Persistent<Function>    fun;

    b.size = 0;
    b.head = b.last = NULL;

    ctx = static_cast<ngx_http_v8_ctx_t *>(
        ngx_http_get_module_ctx(r, ngx_http_v8_module));

    if (ctx == NULL) {
        ctx = static_cast<ngx_http_v8_ctx_t *>(
            ngx_pcalloc(r->pool, sizeof(ngx_http_v8_ctx_t)));
        ngx_http_set_ctx(r, ctx, ngx_http_v8_module);
    }

    v8lcf = static_cast<ngx_http_v8_loc_conf_t *>(
        ngx_http_get_module_loc_conf(r, ngx_http_v8_module));

    if (ctx->next == NULL) {
        fun = v8lcf->process;
    } else {
        fun = ctx->next->fun;
        ctx->next = NULL;
    }
    
    ngx_http_clean_header(r);

    rc = ngx_http_v8_call_handler(r, v8lcf, fun, &b);

    if (rc == NGX_DONE) {
        return;
    }

    /*if (rc > 600) {
        rc = NGX_OK;
    }*/

    if (ctx->done || ctx->next) {
        return;
    }

    if (rc == NGX_OK) {
        rc = NGX_HTTP_OK;
    }


    if (!(rc == NGX_OK || rc == NGX_HTTP_OK)) {
        r->keepalive = 0;
    }

    r->headers_out.status = rc;
    if (r->headers_out.content_type.data == NULL) {
        r->headers_out.content_type.len = sizeof("text/html; charset=utf-8") - 1;
        r->headers_out.content_type.data = reinterpret_cast<u_char *>(
            const_cast<char *>("text/html; charset=utf-8"));
    }
    r->headers_out.content_length_n = b.size;

    ngx_http_send_header(r);

    if (b.head) {
        ngx_http_output_filter(r, b.head);
    }

    ngx_http_send_special(r, NGX_HTTP_LAST);

    // May not use
    ctx->done = 1;

    ngx_http_finalize_request(r, rc);
}

static ngx_int_t
ngx_http_v8_handler(ngx_http_request_t *r)
{
    ngx_http_v8_handler_request(r);
    return NGX_DONE;
}

static void clean(void *data)
{
    method_t *m = static_cast<method_t *>(data);
    HandleScope scope;
    Local<Value> v = m->fun->Call(m->recv, 0, NULL);
    m->recv.Dispose();
    m->fun.Dispose();
}

static Handle<Value> BindPool(const Arguments& args)
{
    ngx_http_request_t *r;
    ngx_pool_cleanup_t *c;
    method_t *m;

    r = static_cast<ngx_http_request_t *>(Unwrap(args.This(), 0));
    m = static_cast<method_t *>(ngx_pcalloc(r->pool, sizeof(method_t)));

    HandleScope scope;
    Local<Function> f = Local<Function>::Cast(Local<Object>::Cast(args[0]));
    Local<Object> recv = Local<Object>::Cast(args[1]);
    m->fun = Persistent<Function>::New(f);
    m->recv = Persistent<Object>::New(recv);

    c = ngx_pool_cleanup_add(r->pool, 0);
    c->data = m;
    c->handler = &clean;

    return args[1];
}

static Handle<Value> ReadBody(const Arguments& args)
{
    ngx_http_request_t *r;
    ngx_http_v8_ctx_t *ctx;

    HandleScope scope;
    Handle<Object> self = args.This();
    Handle<Function> post_fun = Handle<Function>::Cast(args[0]);

    r = static_cast<ngx_http_request_t *>(Unwrap(self, 0));
    ctx = static_cast<ngx_http_v8_ctx_t *>(
        ngx_http_get_module_ctx(r, ngx_http_v8_module));
    ctx->next = static_cast<function_t *>(
        ngx_pcalloc(r->pool, sizeof(function_t)));
    ctx->next->fun = Persistent<Function>::New(post_fun);
    // TODO: dispose handle when request finished instead of depending on gc
    ctx->next->fun.MakeWeak(NULL, &HandleDispose);

    r->request_body_in_single_buf = 1;
    r->request_body_in_persistent_file = 1;
    r->request_body_in_clean_file = 1;

    return Integer::New(ngx_http_read_client_request_body(r, ngx_http_v8_handler_request));
}

static Handle<Value> Write(const Arguments& args)
{
    ngx_chain_t         *out;
    ngx_http_request_t  *r;
    ngx_buf_t           *b;
    brigade_t           *bri;
    size_t              len;
    u_char              *p;

    HandleScope scope;
    Local<Object> self = args.This();
    String::Utf8Value value(args[0]);
    r = static_cast<ngx_http_request_t*>(Unwrap(self, 0));
    bri = static_cast<brigade_t*>(Unwrap(self, 1));

    len = value.length();
    p = static_cast<u_char*>(ngx_pnalloc(r->pool, len));
    ngx_memcpy(p, *value, len);

    bri->size += len;

    b = static_cast<ngx_buf_t *>(ngx_pcalloc(r->pool, sizeof(ngx_buf_t)));
    if (b == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "Failed to allocate response buffer.");
    }
    b->memory = 1;
    b->pos = p;
    b->last = p + len;
    b->last_buf = 1;

    out = ngx_alloc_chain_link(r->pool);
    out->buf = b;
    out->next = NULL;

    if (bri->head == NULL) {
        bri->head = bri->last = out;
    } else {
        bri->last->buf->last_buf = 0;
        bri->last->next = out;
        bri->last = out;
    }

    return Undefined();
}

static Handle<Value> AddResponseHeader(const Arguments& args)
{
    ngx_http_request_t  *r;
    ngx_table_elt_t     *header;
    u_char              *contentLength;
    size_t              len;

    HandleScope scope;
    Local<Object> self = args.This();
    String::AsciiValue key(args[0]);
    String::AsciiValue value(args[1]);
    r = static_cast<ngx_http_request_t*>(Unwrap(self, 0));
    header = static_cast<ngx_table_elt_t*>(ngx_list_push(&r->headers_out.headers));
    header->hash = 1;

    len = key.length();
    header->key.len = len;
    header->key.data = static_cast<u_char*>(ngx_pnalloc(r->pool, len));
    ngx_memcpy(header->key.data, *key, len);

    len = value.length();
    header->value.len = len;
    header->value.data = static_cast<u_char*>(ngx_pnalloc(r->pool, len));
    ngx_memcpy(header->value.data, *value, len);

    contentLength = reinterpret_cast<u_char*>(const_cast<char*>("Content-Length"));
    if (header->key.len == sizeof("Content-Length") - 1
        && ngx_strncasecmp(header->key.data, contentLength,
                           sizeof("Content-Length") - 1) == 0)
    {
        r->headers_out.content_length_n = static_cast<off_t>(atoi(*value));
        r->headers_out.content_length = header;
    }
    return Undefined();
}

static Handle<Value> Log(const Arguments& args)
{
    HandleScope scope;
    Handle<Value> arg = args[0];
    String::Utf8Value value(arg);
    printf("%s\n", *value);
    //cout << (*value) << endl;
    return Undefined();
}

/*static Handle<Value> Lookup(const Arguments& args) 
{
    return Undefined();
}*/

/*static Handle<ObjectTemplate> createV8Com()
{
    HandleScope scope;
    Handle<ObjectTemplate> v8com = ObjectTemplate::New();
    Handle<ObjectTemplate> components = ObjectTemplate::New();
    Handle<ObjectTemplate> classes = ObjectTemplate::New();
    Handle<ObjectTemplate> interfaces = ObjectTemplate::New();
    return scope.Close(v8com);
}*/

static void *
ngx_http_v8_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_v8_loc_conf_t   *conf;

    conf = static_cast<ngx_http_v8_loc_conf_t*>(
        ngx_pcalloc(cf->pool, sizeof(ngx_http_v8_loc_conf_t)));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    return conf;
}

static char*
ngx_http_v8_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    return NGX_CONF_OK;
}

/*static void GCCall() {
    cout << "GC" << endl;
}*/

static Handle<Value> read_file(const char* filename) {
    int fd;
    struct stat sb;
    unsigned char *bytes;

    HandleScope scope;
    
    if ((fd = open(filename, O_RDONLY)) == -1) {
        fprintf(stderr, "open: %s: %s\n", strerror(errno), filename);
        return Null();
    }

    fstat(fd, &sb);

    bytes = static_cast<unsigned char*>(mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0));

    if (close(fd) != 0) {
        fprintf(stderr, "close: %s: %s\n", strerror(errno), filename);
        return Null();
    }

    Local<String> result = String::New(reinterpret_cast<const char*>(bytes), sb.st_size);
    munmap(bytes, sb.st_size);

    return scope.Close(result);
}

static int execute_script(const char* file)
{
    HandleScope scope;

    Handle<Value> source = read_file(file);
    if (!source->IsString() || Handle<String>::Cast(source)->Length() == 0) {
        return -1;
    }

    Local<String> filename = String::New(file);
    Local<Script> script = Script::Compile(Handle<String>::Cast(source), filename);

    TryCatch trycatch;
    Local<Value> result = script->Run();
    if (trycatch.HasCaught()) {
        Local<Value> st = trycatch.StackTrace();
        String::AsciiValue st_str(st);
        fprintf(stderr, "run: %s\n", *st_str);
        return -1;
    }

    scope.Close(result);
    return 0;
}

static char *
ngx_http_v8(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_v8_loc_conf_t      *v8lcf;
    ngx_http_core_loc_conf_t    *clcf;
    ngx_str_t                   *value;
    const char                  *filename;

    v8lcf = static_cast<ngx_http_v8_loc_conf_t *>(conf);
    value = static_cast<ngx_str_t *>(cf->args->elts);

    clcf = static_cast<ngx_http_core_loc_conf_t *>(
        ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module));
    clcf->handler = ngx_http_v8_handler;

    HandleScope scope;
    if (v8lcf->context.IsEmpty()) {
        V8::SetFlagsFromString("--expose_debug_as debug", strlen("--expose_debug_as debug"));
        Local<ObjectTemplate> global = ObjectTemplate::New();
        Local<ObjectTemplate> components = ObjectTemplate::New();
        global->Set(String::New("log"), FunctionTemplate::New(Log));
        if (v8lcf->classes.IsEmpty()) {
            v8lcf->classes = Persistent<ObjectTemplate>::New(ObjectTemplate::New());
        }
        components->Set(String::New("classes"), v8lcf->classes);
        //components->Set(String::New("interfaces"), v8lcf->interfaces);
        //components->Set(String::New("lookup"), FunctionTemplate::New(Lookup));
        global->Set(String::New("Components"), components);

        /*Local<FunctionTemplate> xhr = FunctionTemplate::New(xhr::Initialize);
        xhr->SetClassName(String::New("XMLHttpRequest"));
        Local<ObjectTemplate> xhrInstance = xhr->InstanceTemplate();
        Local<ObjectTemplate> xhrPrototype = xhr->PrototypeTemplate();
        xhrPrototype->Set(String::New("open"), FunctionTemplate::New(xhr::Open));
        xhrPrototype->Set(String::New("send"), FunctionTemplate::New(xhr::Send));
        global->Set(String::New("XMLHttpRequest"), xhr);*/

        //const char *extensionNames[] = { "v8/gc" };
        //ExtensionConfiguration extensions(sizeof(extensionNames)/sizeof(extensionNames[0]),
        //                                  extensionNames);
        v8lcf->context = Context::New(NULL, global);
        //v8lcf->context = Context::New(&extensions, global);
    }

    Context::Scope context_scope(v8lcf->context);
    //V8::SetGlobalGCEpilogueCallback(GCCall);
    filename = reinterpret_cast<const char*>(value[1].data);
    if (execute_script(filename) == -1) {
        return static_cast<char*>(NGX_CONF_ERROR);
    }

    if (v8lcf->process.IsEmpty() &&
        v8lcf->context->Global()->Has(String::New("process"))) {
        Local<Value> process_val = v8lcf->context->Global()->Get(String::New("process"));
        Local<Function> process_fun = Local<Function>::Cast(process_val);
        v8lcf->process = Persistent<Function>::New(process_fun);
    }

    return NGX_CONF_OK;
}

static char *
ngx_http_v8com(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_v8_loc_conf_t     *v8lcf;
    ngx_str_t                  *value;
    void                       *handle;

    v8lcf = static_cast<ngx_http_v8_loc_conf_t *>(conf);
    value = static_cast<ngx_str_t *>(cf->args->elts);

    HandleScope scope;

    if (v8lcf->classes.IsEmpty()) {
        Handle<ObjectTemplate> classes = ObjectTemplate::New();
        v8lcf->classes = Persistent<ObjectTemplate>::New(classes);
    }
    if (v8lcf->interfaces.IsEmpty()) {
        Handle<ObjectTemplate> interfaces = ObjectTemplate::New();
        v8lcf->interfaces = Persistent<ObjectTemplate>::New(interfaces);
    }

    Handle<String> name = String::New(reinterpret_cast<const char*>(value[1].data));
    if ((handle = dlopen(reinterpret_cast<const char*>(value[2].data), RTLD_LAZY)) == NULL) {
        fprintf(stderr, "dlopen: %s: %s\n", dlerror(), value[2].data);
        return static_cast<char*>(NGX_CONF_ERROR);
    }
    Handle<Template>(*createObject)();

    createObject = reinterpret_cast<Handle<Template> (*)()>(dlsym(handle, "createObject"));
    v8lcf->classes->Set(name, createObject());
    //dlclose(handle);

    return NGX_CONF_OK;
}

