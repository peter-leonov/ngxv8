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

using namespace v8;

extern ngx_module_t  ngx_http_v8_module;

static char *ngx_http_v8(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_v8com(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void *ngx_http_v8_create_main_conf(ngx_conf_t *cf);
static void *ngx_http_v8_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_v8_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_v8_init_process(ngx_cycle_t *cycle);
static Handle<Value> Log(const Arguments& args);
static Handle<Value> BindPool(const Arguments& args);
static Handle<Value> InternalRedirect(const Arguments& args);
static Handle<Value> ReadBody(const Arguments& args);
static Handle<Value> SendFile(const Arguments& args);
static Handle<Value> SetTimeout(const Arguments& args);
static Handle<Value> Handshake(const Arguments& args);
static Handle<Value> Write(const Arguments& args);
static Handle<Value> AddResponseHeader(const Arguments& args);
static void *Unwrap(Handle<Object> obj, int field);

template <class T>
inline T ptr_cast(void *p) {
    return static_cast<T>(p);
}

typedef struct {
    Persistent<Function> fun;
} function_t;

typedef struct {
    Persistent<Object> recv;
    Persistent<Function> fun;
} method_t;

typedef struct {
    ngx_chain_t *head;
    ngx_chain_t *tail;
    size_t size;
} brigade_t;

typedef struct {
    ngx_uint_t agent_port;
    ngx_array_t components;
    ngx_array_t scripts;
} ngx_http_v8_main_conf_t;

typedef struct {
    Persistent<Context> context;
    Persistent<Function> process;
    Persistent<ObjectTemplate> classes;
    //Persistent<ObjectTemplate> interfaces;
    Persistent<FunctionTemplate> request_tmpl;
    Persistent<FunctionTemplate> response_tmpl;
} ngx_http_v8_loc_conf_t;

typedef struct {
    Persistent<Object> headers;
    function_t *next;
    ngx_uint_t done;
    ngx_uint_t header_sent;
    ngx_str_t redirect_uri;
    ngx_str_t redirect_args;
    brigade_t *out;
} ngx_http_v8_ctx_t;

static ngx_command_t  ngx_http_v8_commands[] = {

    { ngx_string("v8"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_http_v8,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL },

    { ngx_string("v8com"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
        ngx_http_v8com,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL },

    { ngx_string("v8agent"),
        NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_num_slot,
        NGX_HTTP_MAIN_CONF_OFFSET,
        offsetof(ngx_http_v8_main_conf_t, agent_port),
        NULL },

    ngx_null_command
};

static ngx_http_module_t ngx_http_v8_module_ctx = {
    NULL,                                /* preconfiguration */
    NULL,                                /* postconfiguration */

    ngx_http_v8_create_main_conf,        /* create main configuration */
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
    ngx_core_conf_t         *ccf;
    ngx_http_v8_main_conf_t *v8mcf;

    v8mcf = static_cast<ngx_http_v8_main_conf_t*>(
        ngx_http_cycle_get_module_main_conf(cycle, ngx_http_v8_module));

    if (v8mcf->agent_port == NGX_CONF_UNSET_UINT) {
        return NGX_OK;
    }

    ccf = ptr_cast<ngx_core_conf_t*>(ngx_get_conf(cycle->conf_ctx, ngx_core_module));

    if (ccf->worker_processes > 1) {
        printf("v8agent could be active only when worker_processes = 1.\n");
        return NGX_ERROR;
    }

    Debug::EnableAgent("ngxv8", v8mcf->agent_port);
    printf("v8 debug agent is started: 127.0.0.1:%d\n", v8mcf->agent_port);
    
    return NGX_OK;
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

// --- Request Properties ---

static Handle<Value> GetUri(Local<String> name, const AccessorInfo& info)
{
    ngx_http_request_t *r;

    r = static_cast<ngx_http_request_t*>(Unwrap(info.Holder(), 0));

    return String::New(ptr_cast<const char*>(r->uri.data), r->uri.len);
}

static Handle<Value> GetMethod(Local<String> name, const AccessorInfo& info)
{
    ngx_http_request_t *r;

    r = static_cast<ngx_http_request_t*>(Unwrap(info.Holder(), 0));

    return String::New(ptr_cast<const char*>(r->method_name.data),
                       r->method_name.len);
}

static Handle<Value> GetUserAgent(Local<String> name, const AccessorInfo& info)
{
    ngx_http_request_t *r;
    ngx_str_t          ua;

    r = static_cast<ngx_http_request_t*>(Unwrap(info.Holder(), 0));
    ua = r->headers_in.user_agent->value;

    return String::New(ptr_cast<const char*>(ua.data), ua.len);
}

static Handle<Value> GetArgs(Local<String> name, const AccessorInfo& info)
{
    ngx_http_request_t *r;

    r = static_cast<ngx_http_request_t*>(Unwrap(info.Holder(), 0));

    return String::New(ptr_cast<const char*>(r->args.data), r->args.len);
}

static Handle<Value> GetBodyBuf(Local<String> name, const AccessorInfo& info)
{
    ngx_http_request_t *r;
    size_t             len;

    r = static_cast<ngx_http_request_t *>(Unwrap(info.Holder(), 0));
    if (r->request_body == NULL
        || r->request_body->temp_file
        || r->request_body->bufs == NULL) {
        return Undefined();
    }

    len = r->request_body->bufs->buf->last - r->request_body->bufs->buf->pos;

    if (len == 0) {
        return Undefined();
    }

    return String::New(ptr_cast<const char*>(r->request_body->bufs->buf->pos),
                       len);
}

static Handle<Value> GetBodyFileOrBuf(Local<String> name, const AccessorInfo& info)
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

static Handle<Value> GetHeader(Local<String> name, const AccessorInfo& info)
{
    ngx_http_request_t *r;
    ngx_http_v8_ctx_t  *ctx;
    ngx_list_part_t    *part;
    ngx_table_elt_t    *h;
    unsigned int       i;

    HandleScope scope;
    Local<Object> result = Object::New();

    r = static_cast<ngx_http_request_t*>(Unwrap(info.Holder(), 0));
    ctx = static_cast<ngx_http_v8_ctx_t*>(
        ngx_http_get_module_ctx(r, ngx_http_v8_module));

    // isn't needed? because call by NewSymbol
    if (!ctx->headers.IsEmpty()) {
        return scope.Close(ctx->headers);
    }

    part = &r->headers_in.headers.part;
    h = static_cast<ngx_table_elt_t*>(part->elts);

    for (i = 0; ; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            h = static_cast<ngx_table_elt_t*>(part->elts);
            i = 0;
        }

        result->Set(String::New(ptr_cast<const char*>(h[i].key.data), h[i].key.len),
                    String::New(ptr_cast<const char*>(h[i].value.data), h[i].value.len));
    }

    ctx->headers = Persistent<Object>::New(result);
    ctx->headers.MakeWeak(NULL, &HandleDispose);

    return scope.Close(result);
}

static Handle<Value> RealPath(Local<String> name, const AccessorInfo& info)
{
    ngx_http_request_t  *r;
    u_char              *last;
    size_t              root;
    ngx_str_t           path;

    HandleScope scope;
    Local<Object> self = info.Holder();
    r = static_cast<ngx_http_request_t*>(Unwrap(self, 0));

    last = ngx_http_map_uri_to_path(r, &path, &root, 0);
    path.len = last - path.data;

    return String::New(ptr_cast<const char*>(path.data), path.len);
}

// --- Request Method ---

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
    p = ptr_cast<u_char*>(*name);
    hash = ngx_hash_strlow(lowcase, p, len);
    var.len = len;
    var.data = lowcase;
    vv = ngx_http_get_variable(r, &var, hash, 1);

    if (vv->not_found) {
        return Undefined();
    }
    return String::New(ptr_cast<const char*>(vv->data), vv->len);
}

// --- Response Properties ---

static Handle<Value> GetRespContentType(Local<String> name, const AccessorInfo& info)
{
    ngx_http_request_t *r = static_cast<ngx_http_request_t*>(Unwrap(info.Holder(), 0));
    return String::New(ptr_cast<const char*>(r->headers_out.content_type.data),
        r->headers_out.content_type.len);
}

static void SetRespContentType(Local<String> name, Local<Value> val, const AccessorInfo& info)
{
    ngx_http_request_t *r;
    u_char             *p;
    int                len;
   
    HandleScope scope;
    r = static_cast<ngx_http_request_t*>(Unwrap(info.Holder(), 0));
    Local<String> value = Local<String>::Cast(val);

    len = value->Utf8Length();
    p = static_cast<u_char*>(ngx_pnalloc(r->pool, len));
    value->WriteUtf8(ptr_cast<char*>(p), len);

    r->headers_out.content_type.data = p;
    r->headers_out.content_type.len = len;
}

static Handle<Value> NewNginxRequest(const Arguments& args)
{
    HandleScope scope;
    Local<Object> self = args.This();
    self->SetInternalField(0, Local<External>::Cast(args[0]));
    return scope.Close(self);
}

static Handle<Value> NewNginxResponse(const Arguments& args)
{
    HandleScope scope;
    Local<Object> self = args.This();
    self->SetInternalField(0, Local<External>::Cast(args[0]));
    return scope.Close(self);
}

static Local<FunctionTemplate> MakeRequestTemplate()
{
    HandleScope scope;
    Local<FunctionTemplate> reqTmpl = FunctionTemplate::New(NewNginxRequest);
    Local<ObjectTemplate> reqInstanceTmpl = reqTmpl->InstanceTemplate();
    reqInstanceTmpl->SetInternalFieldCount(1);
    Local<ObjectTemplate> reqPrototypeTmpl = reqTmpl->PrototypeTemplate();
    reqInstanceTmpl->SetAccessor(String::NewSymbol("uri"), GetUri);
    reqInstanceTmpl->SetAccessor(String::NewSymbol("method"), GetMethod);
    reqInstanceTmpl->SetAccessor(String::NewSymbol("userAgent"), GetUserAgent);
    reqInstanceTmpl->SetAccessor(String::NewSymbol("args"), GetArgs);
    reqInstanceTmpl->SetAccessor(String::NewSymbol("body"), GetBodyFileOrBuf);
    reqInstanceTmpl->SetAccessor(String::NewSymbol("headers"), GetHeader);
    reqInstanceTmpl->SetAccessor(String::NewSymbol("realPath"), RealPath);
    reqPrototypeTmpl->Set(String::New("$"), FunctionTemplate::New(GetVariable));
    reqPrototypeTmpl->Set(String::New("bind"), FunctionTemplate::New(BindPool));
    reqPrototypeTmpl->Set(String::New("forward"), FunctionTemplate::New(InternalRedirect));
    reqPrototypeTmpl->Set(String::New("readBody"), FunctionTemplate::New(ReadBody));
    reqPrototypeTmpl->Set(String::New("sendfile"), FunctionTemplate::New(SendFile));
    reqPrototypeTmpl->Set(String::New("setTimeout"), FunctionTemplate::New(SetTimeout));
    reqPrototypeTmpl->Set(String::New("handshake"), FunctionTemplate::New(Handshake));
    return reqTmpl;
}

static Local<FunctionTemplate> MakeResponseTemplate()
{
    HandleScope scope;
    Local<FunctionTemplate> respTmpl = FunctionTemplate::New(NewNginxResponse);
    Local<ObjectTemplate> respInstanceTmpl = respTmpl->InstanceTemplate();
    respInstanceTmpl->SetInternalFieldCount(1);
    Local<ObjectTemplate> respPrototypeTmpl = respTmpl->PrototypeTemplate();
    respInstanceTmpl->SetAccessor(String::NewSymbol("contentType"),
                                  GetRespContentType, SetRespContentType);
    respPrototypeTmpl->Set(String::New("write"), FunctionTemplate::New(Write));
    respPrototypeTmpl->Set(String::New("addHeader"), FunctionTemplate::New(AddResponseHeader));
    return respTmpl;
}

static Local<Object> WrapRequest(ngx_http_v8_loc_conf_t *v8lcf, ngx_http_request_t *r)
{
    HandleScope scope;
    Handle<Value> argv[1] = { External::New(r) };
    Local<Object> result = v8lcf->request_tmpl->GetFunction()->NewInstance(1, argv);
    return scope.Close(result);
}

static Local<Object> WrapResponse(ngx_http_v8_loc_conf_t *v8lcf, ngx_http_request_t *r)
{
    HandleScope scope;
    Handle<Value> argv[1] = { External::New(r) };
    Local<Object> result = v8lcf->response_tmpl->GetFunction()->NewInstance(1, argv);
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
    Persistent<Function> fun
) {
    ngx_connection_t *c;

    c = r->connection;

    Context::Scope context_scope(v8lcf->context);
    HandleScope scope;

    Local<Object> request_obj = WrapRequest(v8lcf, r);
    Local<Object> response_obj = WrapResponse(v8lcf, r);//, b);
    Handle<Value> argv[2] = { request_obj, response_obj };

    TryCatch trycatch;
    Handle<Value> result = fun->Call(v8lcf->context->Global(), 2, argv);
    if (trycatch.HasCaught()) {
        Local<Value> st = trycatch.StackTrace();
        String::AsciiValue st_str(st);
        fprintf(ngx_daemonized ? stderr : stdout, "call: %s\n", *st_str);
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
ngx_http_v8_handle_request(ngx_http_request_t *r)
{
    ngx_int_t               rc;
    ngx_str_t               uri, args;
    ngx_http_v8_ctx_t       *ctx;
    ngx_http_v8_loc_conf_t  *v8lcf;
    Persistent<Function>    fun;

    ctx = static_cast<ngx_http_v8_ctx_t*>(
        ngx_http_get_module_ctx(r, ngx_http_v8_module));

    if (ctx == NULL) {
        ctx = static_cast<ngx_http_v8_ctx_t*>(
            ngx_pcalloc(r->pool, sizeof(ngx_http_v8_ctx_t)));
        ctx->out = static_cast<brigade_t*>(ngx_palloc(r->pool, sizeof(brigade_t)));
        ctx->out->size = 0;
        ctx->out->head = ctx->out->tail = NULL;
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

    rc = ngx_http_v8_call_handler(r, v8lcf, fun);

    if (rc == NGX_DONE) {
        return;
    }

    if (ctx->redirect_uri.len) {
        uri = ctx->redirect_uri;
        args = ctx->redirect_args;
    } else {
        uri.len = 0;
    }

    ctx->redirect_uri.len = 0;

    /*if (rc > 600) {
        rc = NGX_OK;
    }*/

    if (ctx->done || ctx->next) {
        return;
    }

    if (uri.len) {
        ngx_http_internal_redirect(r, &uri, &args);
        return;
    }

    if (rc == NGX_OK) {
        rc = NGX_HTTP_OK;
    }


    if (!(rc == NGX_OK || rc == NGX_HTTP_OK)) {
        r->keepalive = 0;
    }

    if (r->headers_in.range) {
        r->allow_ranges = 1;
    }

    if (!ctx->header_sent) {
        r->headers_out.status = rc;
        if (r->headers_out.content_type.data == NULL) {
            r->headers_out.content_type.len = sizeof("text/html; charset=utf-8") - 1;
            r->headers_out.content_type.data = ptr_cast<u_char*>(
                const_cast<char*>("text/html; charset=utf-8"));
        }
        r->headers_out.content_length_n = ctx->out->size;

        ngx_http_send_header(r);
    }

    if (ctx->out->head) {
        ngx_http_output_filter(r, ctx->out->head);
    }

    ngx_http_send_special(r, NGX_HTTP_LAST);

    // May not use
    ctx->done = 1;

    ngx_http_finalize_request(r, rc);
}

static ngx_int_t
ngx_http_v8_handler(ngx_http_request_t *r)
{
    ngx_http_v8_handle_request(r);
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

static Handle<Value> InternalRedirect(const Arguments& args)
{
    ngx_http_request_t *r;
    ngx_http_v8_ctx_t  *ctx;
    unsigned int       i;

    HandleScope scope;
    Local<Object> self = args.This();
    Local<String> uri = Local<String>::Cast(args[0]);

    r = static_cast<ngx_http_request_t*>(Unwrap(self, 0));
    ctx = static_cast<ngx_http_v8_ctx_t*>(
        ngx_http_get_module_ctx(r, ngx_http_v8_module));

    ctx->redirect_uri.len = uri->Utf8Length();
    ctx->redirect_uri.data = static_cast<u_char*>(ngx_pnalloc(r->pool, ctx->redirect_uri.len));
    uri->WriteUtf8(ptr_cast<char*>(ctx->redirect_uri.data), ctx->redirect_uri.len);

    for (i = 0; i < ctx->redirect_uri.len; i++) {
        if (ctx->redirect_uri.data[i] == '?') {
            ctx->redirect_args.len = ctx->redirect_uri.len - (i + 1);
            ctx->redirect_args.data = &ctx->redirect_uri.data[i + 1];
            ctx->redirect_uri.len = i;
            return Integer::New(NGX_HTTP_OK);
        }
    }

    return Integer::New(NGX_HTTP_OK);
}

static Handle<Value> ReadBody(const Arguments& args)
{
    ngx_http_request_t *r;
    ngx_http_v8_ctx_t  *ctx;

    HandleScope scope;
    Handle<Object> self = args.This();
    Handle<Function> post_fun = Handle<Function>::Cast(args[0]);

    r = static_cast<ngx_http_request_t*>(Unwrap(self, 0));
    ctx = static_cast<ngx_http_v8_ctx_t*>(
        ngx_http_get_module_ctx(r, ngx_http_v8_module));
    ctx->next = static_cast<function_t*>(
        ngx_pcalloc(r->pool, sizeof(function_t)));
    ctx->next->fun = Persistent<Function>::New(post_fun);
    // TODO: dispose handle when request finished instead of depending on gc
    ctx->next->fun.MakeWeak(NULL, &HandleDispose);

    r->request_body_in_single_buf = 1;
    r->request_body_in_persistent_file = 1;
    r->request_body_in_clean_file = 1;

    return Integer::New(ngx_http_read_client_request_body(r, ngx_http_v8_handle_request));
}

void ngx_http_v8_timeout_handler(ngx_http_request_t *r)
{
    ngx_event_t  *wev;

    wev = r->connection->write;

    if (wev->timedout) {
        wev->timedout = 0;
        ngx_http_v8_handle_request(r);
        return;
    }

    if (ngx_handle_write_event(wev, 0) != NGX_OK) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
    }
}

static Handle<Value> SetTimeout(const Arguments& args)
{
    ngx_http_request_t *r;
    ngx_http_v8_ctx_t  *ctx;
    ngx_msec_t         timeout;

    HandleScope scope;
    Handle<Object> self = args.This();
    Handle<Function> post_fun = Handle<Function>::Cast(args[0]);
    timeout = args[1]->Int32Value();;

    r = static_cast<ngx_http_request_t*>(Unwrap(self, 0));
    ctx = static_cast<ngx_http_v8_ctx_t*>(
        ngx_http_get_module_ctx(r, ngx_http_v8_module));
    ctx->next = static_cast<function_t*>(
        ngx_pcalloc(r->pool, sizeof(function_t)));
    ctx->next->fun = Persistent<Function>::New(post_fun);
    ctx->next->fun.MakeWeak(NULL, &HandleDispose);

    ngx_add_timer(r->connection->write, timeout);

    r->write_event_handler = ngx_http_v8_timeout_handler;

    return Integer::New(r->connection->write->timer.key);
}

static Handle<Value> Handshake(const Arguments& args)
{
    ngx_http_request_t      *r;
    ngx_http_v8_loc_conf_t  *v8lcf;
    ngx_http_v8_ctx_t       *ctx;

    HandleScope scope;
    Local<Object> self = args.This();
    Local<Function> recv_fun = Local<Function>::Cast(args[0]);
    Local<Function> conn_fun = Local<Function>::Cast(args[1]);
    Local<Function> disconn_fun = Local<Function>::Cast(args[2]);

    r = static_cast<ngx_http_request_t*>(Unwrap(self, 0));
    v8lcf = static_cast<ngx_http_v8_loc_conf_t*>(
        ngx_http_get_module_loc_conf(r, ngx_http_v8_module));
    ctx = static_cast<ngx_http_v8_ctx_t*>(
        ngx_http_get_module_ctx(r, ngx_http_v8_module));
    ctx->next = static_cast<function_t*>(
        ngx_pcalloc(r->pool, sizeof(function_t)));

    ctx->next->fun = Persistent<Function>::New(recv_fun);
    ctx->next->fun.MakeWeak(NULL, &HandleDispose);

    r->headers_out.status = 101;
    r->headers_out.status_line.len = sizeof("101 Web Socket Protocol Handshake") - 1;
    r->headers_out.status_line.data = ptr_cast<u_char*>(
            const_cast<char*>("101 Web Socket Protocol Handshake"));
    ngx_http_send_header(r);
    ctx->header_sent = 1;

    if (args[1]->IsFunction()) {
        /*Local<Value> result = */conn_fun->Call(v8lcf->context->Global(), 0, NULL);
    }

    return Integer::New(NGX_AGAIN);
}

static Handle<Value> Write(const Arguments& args)
{
    ngx_chain_t         *out;
    ngx_http_request_t  *r;
    ngx_http_v8_ctx_t   *ctx;
    ngx_buf_t           *b;
    brigade_t           *bri;
    size_t              len;
    u_char              *p;

    HandleScope scope;
    Local<Object> self = args.This();
    Local<String> v = Local<String>::Cast(args[0]);

    r = static_cast<ngx_http_request_t*>(Unwrap(self, 0));
    ctx = static_cast<ngx_http_v8_ctx_t*>(
        ngx_http_get_module_ctx(r, ngx_http_v8_module));

    if (v->IsExternalAscii()) {
        String::ExternalAsciiStringResource *res = v->GetExternalAsciiStringResource();
        len = res->length();
        p = ptr_cast<u_char*>(const_cast<char*>(res->data()));
    } else {
        len = v->Utf8Length();
        p = static_cast<u_char*>(ngx_pnalloc(r->pool, len));
        v->WriteUtf8(ptr_cast<char*>(p), len);
    }

    bri = ctx->out;
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
    b->last_in_chain = 1;

    out = ngx_alloc_chain_link(r->pool);
    out->buf = b;
    out->next = NULL;

    if (bri->head == NULL) {
        bri->head = bri->tail = out;
    } else {
        bri->tail->buf->last_buf = 0;
        bri->tail->next = out;
        bri->tail = out;
    }

    return Undefined();
}

static Handle<Value> SendFile(const Arguments& args)
{
    ngx_http_request_t          *r;
    ngx_http_core_loc_conf_t    *clcf;
    ngx_http_v8_ctx_t           *ctx;
    ngx_buf_t                   *b;
    ngx_str_t                   path;
    off_t                       offset;
    size_t                      bytes;
    ngx_open_file_info_t        of;
    brigade_t                   *bri;
    ngx_chain_t                 *out;

    HandleScope scope;
    Local<Object> self = args.This();
    
    String::Utf8Value filename(args[0]);
    offset = args[1]->Int32Value();
    bytes = args[2]->Int32Value();

    r = static_cast<ngx_http_request_t*>(Unwrap(self, 0));
    ctx = static_cast<ngx_http_v8_ctx_t*>(
        ngx_http_get_module_ctx(r, ngx_http_v8_module));
    clcf = static_cast<ngx_http_core_loc_conf_t*>(
        ngx_http_get_module_loc_conf(r, ngx_http_core_module));

    path.len = filename.length();
    path.data = static_cast<u_char*>(ngx_pnalloc(r->pool, path.len + 1));
    ngx_cpystrn(path.data, ptr_cast<u_char*>(*filename), path.len + 1);

    ngx_memzero(&of, sizeof(ngx_open_file_info_t));

    of.directio = clcf->directio;
    of.valid = clcf->open_file_cache_valid;
    of.min_uses = clcf->open_file_cache_min_uses;
    of.errors = clcf->open_file_cache_errors;
    of.events = clcf->open_file_cache_events;

    if (ngx_open_cached_file(clcf->open_file_cache, &path, &of, r->pool) != NGX_OK) {   
        if (of.err == 0) {
            return False();;
        }

        ngx_log_error(NGX_LOG_CRIT, r->connection->log, ngx_errno,
                "%s \"%s\" failed", of.failed, *filename);
        return False();
    }

    if (offset == -1) {
        offset = 0;
    }

    if (bytes == 0) {
        bytes = of.size - offset;
    }

    b = static_cast<ngx_buf_t*>(ngx_calloc_buf(r->pool));
    b->file = static_cast<ngx_file_t*>(ngx_pcalloc(r->pool, sizeof(ngx_file_t)));

    b->in_file = 1;
    b->last_buf = 1;
    b->last_in_chain = 1;

    b->file_pos = offset;
    b->file_last = offset + bytes;

    b->file->fd = of.fd;
    b->file->name = path;
    b->file->log = r->connection->log;
    b->file->directio = of.is_directio;

    out = ngx_alloc_chain_link(r->pool);
    out->buf = b;
    out->next = NULL;

    bri = ctx->out;
    bri->size += bytes;

    if (bri->head == NULL) {
        bri->head = bri->tail = out;
    } else {
        bri->tail->buf->last_buf = 0;
        bri->tail->next = out;
        bri->tail = out;
    }

    return True();
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

    contentLength = ptr_cast<u_char*>(const_cast<char*>("Content-Length"));
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
    Local<Value> arg = args[0];
    String::Utf8Value value(arg);
    printf("%s\n", *value);
    return Undefined();
}

static Handle<Value> Dump(const Arguments& args)
{
    HandleScope scope;
    String::AsciiValue value(args[0]);
    for (int i = 0; i < value.length(); i++) {
        printf("%c", (*value)[i]);
    }
    printf("\n");
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
ngx_http_v8_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_v8_main_conf_t *conf;

    conf = static_cast<ngx_http_v8_main_conf_t*>(
        ngx_pcalloc(cf->pool, sizeof(ngx_http_v8_main_conf_t)));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->agent_port = NGX_CONF_UNSET_UINT;

    return conf;
}

static void *
ngx_http_v8_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_v8_loc_conf_t *conf;

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

    Local<String> result = String::New(ptr_cast<const char*>(bytes), sb.st_size);
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
        //V8::SetFlagsFromString("--expose_debug_as debug", strlen("--expose_debug_as debug"));
        Local<ObjectTemplate> global = ObjectTemplate::New();
        Local<ObjectTemplate> components = ObjectTemplate::New();
        global->Set(String::NewSymbol("log"), FunctionTemplate::New(Log));
        global->Set(String::NewSymbol("dump"), FunctionTemplate::New(Dump));
        if (v8lcf->classes.IsEmpty()) {
            v8lcf->classes = Persistent<ObjectTemplate>::New(ObjectTemplate::New());
        }
        components->Set(String::New("classes"), v8lcf->classes);
        //components->Set(String::New("interfaces"), v8lcf->interfaces);
        //components->Set(String::New("lookup"), FunctionTemplate::New(Lookup));
        global->Set(String::New("Components"), components);

        v8lcf->request_tmpl = Persistent<FunctionTemplate>::New(MakeRequestTemplate());
        global->Set(String::New("NginxRequest"), v8lcf->request_tmpl);

        v8lcf->response_tmpl = Persistent<FunctionTemplate>::New(MakeResponseTemplate());
        global->Set(String::New("NginxResponse"), v8lcf->response_tmpl);

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
    filename = ptr_cast<const char*>(value[1].data);
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

    v8lcf = static_cast<ngx_http_v8_loc_conf_t*>(conf);
    value = static_cast<ngx_str_t*>(cf->args->elts);

    HandleScope scope;

    if (v8lcf->classes.IsEmpty()) {
        Handle<ObjectTemplate> classes = ObjectTemplate::New();
        v8lcf->classes = Persistent<ObjectTemplate>::New(classes);
    }
    /*if (v8lcf->interfaces.IsEmpty()) {
        Handle<ObjectTemplate> interfaces = ObjectTemplate::New();
        v8lcf->interfaces = Persistent<ObjectTemplate>::New(interfaces);
    }*/

    Handle<String> name = String::New(ptr_cast<const char*>(value[1].data));
    if ((handle = dlopen(ptr_cast<const char*>(value[2].data), RTLD_LAZY)) == NULL) {
        fprintf(stderr, "dlopen: %s: %s\n", dlerror(), value[2].data);
        return static_cast<char*>(NGX_CONF_ERROR);
    }
    Handle<Template>(*createObject)();

    createObject = reinterpret_cast<Handle<Template> (*)()>(dlsym(handle, "createObject"));
    v8lcf->classes->Set(name, createObject());
    //dlclose(handle);

    return NGX_CONF_OK;
}
