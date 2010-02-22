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

using namespace v8;

extern ngx_module_t  ngx_http_v8_module;

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
    //ngx_array_t components;
    //ngx_array_t scripts;
} ngx_http_v8_main_conf_t;

typedef struct {
    Persistent<Context> context;
    Persistent<Function> process;
    Persistent<ObjectTemplate> classes;
    //Persistent<ObjectTemplate> interfaces;
    Persistent<FunctionTemplate> request_tmpl;
    Persistent<FunctionTemplate> response_tmpl;
    Persistent<FunctionTemplate> evt_update_timer;
    Persistent<FunctionTemplate> evt_register_fd;
    ngx_uint_t filter_enabled;
} ngx_http_v8_loc_conf_t;

typedef struct {
    Persistent<Object> headers;
    function_t *next;
    ngx_uint_t done;
    ngx_uint_t header_sent;
    ngx_str_t redirect_uri;
    ngx_str_t redirect_args;
    brigade_t *in;
    brigade_t *out;
    //ngx_uint_t filtered;
} ngx_http_v8_ctx_t;

//static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
//static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;

class Ngxv8 {
    public:
        /* Utilities */
        static void DisposeHandle(Persistent<Value> handle, void *p);
        static void Clean(void *data);
        static Local<FunctionTemplate> MakeRequestTemplate();
        static Local<FunctionTemplate> MakeResponseTemplate();
        static Local<Object> WrapRequest(ngx_http_v8_loc_conf_t *v8lcf,
                                         ngx_http_request_t *r);
        static Local<Object> WrapResponse(ngx_http_v8_loc_conf_t *v8lcf,
                                          ngx_http_request_t *r);
        static void* Unwrap(Handle<Object> obj, int field);
        static Handle<Value> Log(const Arguments& args);

        /* Nginx Configuration */
        //static ngx_int_t FilterInit(ngx_conf_t *cf);
        static void* CreateMainConf(ngx_conf_t *cf);
        static void* CreateLocConf(ngx_conf_t *cf);
        static char* MergeLocConf(ngx_conf_t *cf, void *parent, void *child);
        static char* V8(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
        //static char* V8Filter(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
        static char* V8Com(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
        static ngx_int_t InitProcess(ngx_cycle_t *cycle);

        /* Handlers */
        //static ngx_int_t HeaderFilter(ngx_http_request_t *r);
        //static ngx_int_t BodyFilter(ngx_http_request_t *r, ngx_chain_t *in);
        static ngx_int_t V8Handler(ngx_http_request_t *r);
        static void HandleRequest(ngx_http_request_t *r);
        static ngx_int_t CallHandler(ngx_http_request_t *r,
                                     ngx_http_v8_loc_conf_t *v8lcf,
                                     Persistent<Function> fun);
        static void TimeoutHandler(ngx_http_request_t *r);
    private:
        static Handle<Value> ReadFile_(const char* filename);
        static int ExecuteScript_(const char* file);
        static ngx_http_v8_ctx_t* GetContext_(ngx_http_request_t *r);
};

class NginxRequest {
    public:
        static Handle<Value> New(const Arguments& args);
        static Handle<Value> GetVariable(const Arguments& args);
        static Handle<Value> BindPool(const Arguments& args);
        static Handle<Value> Forward(const Arguments& args);
        static Handle<Value> IO(const Arguments& args);
        static Handle<Value> ReadBody(const Arguments& args);
        static Handle<Value> SendFile(const Arguments& args);
        static Handle<Value> SetTimeout(const Arguments& args);
        static Handle<Value> HandShake(const Arguments& args);
        //static Handle<Value> Upstream(const Arguments& args);
        static Handle<Value> GetUri(Local<String> name,
                                    const AccessorInfo& info);
        static Handle<Value> GetMethod(Local<String> name,
                                       const AccessorInfo& info);
        static Handle<Value> GetUserAgent(Local<String> name,
                                          const AccessorInfo& info);
        static Handle<Value> GetArgs(Local<String> name,
                                     const AccessorInfo& info);
        static Handle<Value> GetBodyBuffer(Local<String> name,
                                           const AccessorInfo& info);
        static Handle<Value> GetBodyFileOrBuffer(Local<String> name,
                                                 const AccessorInfo& info);
        static void SetBodyBuffer(Local<String> name,
                                  Local<Value> val,
                                  const AccessorInfo& info);
        static Handle<Value> GetHeader(Local<String> name,
                                       const AccessorInfo& info);
        static Handle<Value> GetRealPath(Local<String> name,
                                         const AccessorInfo& info);
};

class NginxResponse {
    public:
        static Handle<Value> New(const Arguments& args);
        static Handle<Value> Write(const Arguments& args);
        static Handle<Value> AddResponseHeader(const Arguments& args);
        static Handle<Value> GetRespContentType(Local<String> name,
                                                const AccessorInfo& info);
        static void SetRespContentType(Local<String> name,
                                       Local<Value> val,
                                       const AccessorInfo& info);
};

class NginxEvent {
    public:
        static void IOHandler(ngx_event_t *ev);
        static Handle<Value> UpdateTimer(const Arguments& args);
        static Handle<Value> RegisterFd(const Arguments& args);
};

void Ngxv8::DisposeHandle(Persistent<Value> handle, void *p) {
    handle.Dispose();
}

void Ngxv8::Clean(void *data) {
    method_t *m = static_cast<method_t *>(data);
    HandleScope scope;
    Local<Value> v = m->fun->Call(m->recv, 0, NULL);
    m->recv.Dispose();
    m->fun.Dispose();
}

Local<FunctionTemplate> Ngxv8::MakeRequestTemplate() {
    HandleScope scope;
    Local<FunctionTemplate> reqTmpl = FunctionTemplate::New(NginxRequest::New);
    reqTmpl->SetClassName(String::NewSymbol("NginxRequest"));
    Local<ObjectTemplate> reqInstanceTmpl = reqTmpl->InstanceTemplate();
    reqInstanceTmpl->SetInternalFieldCount(1);
    Local<ObjectTemplate> reqPrototypeTmpl = reqTmpl->PrototypeTemplate();
    reqInstanceTmpl->SetAccessor(String::NewSymbol("uri"),
                                 NginxRequest::GetUri);
    reqInstanceTmpl->SetAccessor(String::NewSymbol("method"),
                                 NginxRequest::GetMethod);
    reqInstanceTmpl->SetAccessor(String::NewSymbol("userAgent"),
                                 NginxRequest::GetUserAgent);
    reqInstanceTmpl->SetAccessor(String::NewSymbol("args"),
                                 NginxRequest::GetArgs);
    reqInstanceTmpl->SetAccessor(String::NewSymbol("body"),
                                 NginxRequest::GetBodyFileOrBuffer,
                                 NginxRequest::SetBodyBuffer);
    reqInstanceTmpl->SetAccessor(String::NewSymbol("headers"),
                                 NginxRequest::GetHeader);
    reqInstanceTmpl->SetAccessor(String::NewSymbol("realPath"),
                                 NginxRequest::GetRealPath);
    reqPrototypeTmpl->Set(String::NewSymbol("$"),
                          FunctionTemplate::New(NginxRequest::GetVariable));
    reqPrototypeTmpl->Set(String::NewSymbol("bind"),
                          FunctionTemplate::New(NginxRequest::BindPool));
    reqPrototypeTmpl->Set(String::NewSymbol("forward"),
                          FunctionTemplate::New(NginxRequest::Forward));
    reqPrototypeTmpl->Set(String::NewSymbol("io"),
                          FunctionTemplate::New(NginxRequest::IO));
    reqPrototypeTmpl->Set(String::NewSymbol("readBody"),
                          FunctionTemplate::New(NginxRequest::ReadBody));
    reqPrototypeTmpl->Set(String::NewSymbol("sendfile"),
                          FunctionTemplate::New(NginxRequest::SendFile));
    reqPrototypeTmpl->Set(String::NewSymbol("setTimeout"),
                          FunctionTemplate::New(NginxRequest::SetTimeout));
    reqPrototypeTmpl->Set(String::NewSymbol("handshake"),
                          FunctionTemplate::New(NginxRequest::HandShake));
    /*reqPrototypeTmpl->Set(String::NewSymbol("upstream"),
                          FunctionTemplate::New(NginxRequest::Upstream));*/
    return reqTmpl;
}

Local<FunctionTemplate> Ngxv8::MakeResponseTemplate() {
    HandleScope scope;
    Local<FunctionTemplate> respTmpl = FunctionTemplate::New(NginxResponse::New);
    respTmpl->SetClassName(String::NewSymbol("NginxResponse"));
    Local<ObjectTemplate> respInstanceTmpl = respTmpl->InstanceTemplate();
    respInstanceTmpl->SetInternalFieldCount(1);
    Local<ObjectTemplate> respPrototypeTmpl = respTmpl->PrototypeTemplate();
    respInstanceTmpl->SetAccessor(String::NewSymbol("contentType"),
                                  NginxResponse::GetRespContentType,
                                  NginxResponse::SetRespContentType);
    respPrototypeTmpl->Set(String::NewSymbol("write"),
                           FunctionTemplate::New(NginxResponse::Write));
    respPrototypeTmpl->Set(String::NewSymbol("addHeader"),
                           FunctionTemplate::New(NginxResponse::AddResponseHeader));
    return respTmpl;
}

Local<Object> Ngxv8::WrapRequest(ngx_http_v8_loc_conf_t *v8lcf,
                                 ngx_http_request_t *r) {
    HandleScope scope;
    Handle<Value> argv[1] = { External::New(r) };
    Local<Object> result = v8lcf->request_tmpl->GetFunction()->NewInstance(1, argv);
    return scope.Close(result);
}

Local<Object> Ngxv8::WrapResponse(ngx_http_v8_loc_conf_t *v8lcf, ngx_http_request_t *r) {
    HandleScope scope;
    Handle<Value> argv[1] = { External::New(r) };
    Local<Object> result = v8lcf->response_tmpl->GetFunction()->NewInstance(1, argv);
    return scope.Close(result);
}

void* Ngxv8::Unwrap(Handle<Object> obj, int field) {
    return Handle<External>::Cast(obj->GetInternalField(field))->Value();
}

Handle<Value> Ngxv8::Log(const Arguments& args) {
    HandleScope scope;
    Local<Value> arg = args[0];
    String::Utf8Value value(arg);
    printf("%s\n", *value);
    return Undefined();
}

// --- Request Method ---

Handle<Value> NginxRequest::New(const Arguments& args) {
    HandleScope scope;
    Local<Object> self = args.This();
    self->SetInternalField(0, Local<External>::Cast(args[0]));
    return scope.Close(self);
}

Handle<Value> NginxRequest::GetVariable(const Arguments& args) {
    ngx_http_request_t          *r;
    size_t                      len;
    u_char                      *p, *lowcase;
    ngx_str_t                   var;
    ngx_uint_t                  hash;
    ngx_http_variable_value_t   *vv;

    HandleScope scope;
    String::AsciiValue name(args[0]);
    len = name.length();
    r = static_cast<ngx_http_request_t*>(Ngxv8::Unwrap(args.This(), 0));
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

Handle<Value> NginxRequest::BindPool(const Arguments& args) {
    ngx_http_request_t *r;
    ngx_pool_cleanup_t *c;
    method_t *m;

    r = static_cast<ngx_http_request_t *>(Ngxv8::Unwrap(args.This(), 0));
    m = static_cast<method_t *>(ngx_pcalloc(r->pool, sizeof(method_t)));

    HandleScope scope;
    Local<Function> f = Local<Function>::Cast(Local<Object>::Cast(args[0]));
    Local<Object> recv = Local<Object>::Cast(args[1]);
    m->fun = Persistent<Function>::New(f);
    m->recv = Persistent<Object>::New(recv);

    c = ngx_pool_cleanup_add(r->pool, 0);
    c->data = m;
    c->handler = &Ngxv8::Clean;

    return args[1];
}

Handle<Value> NginxRequest::Forward(const Arguments& args) {
    ngx_http_request_t *r;
    ngx_http_v8_ctx_t  *ctx;
    unsigned int       i;

    HandleScope scope;
    Local<Object> self = args.This();
    Local<String> uri = Local<String>::Cast(args[0]);

    r = static_cast<ngx_http_request_t*>(Ngxv8::Unwrap(self, 0));
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

void NginxEvent::IOHandler(ngx_event_t *ev) {
    ngx_connection_t *c;
    method_t         *m;

    c = static_cast<ngx_connection_t*>(ev->data);
    m = static_cast<method_t*>(c->data);

    HandleScope scope;

    Handle<Value> argv[2] = {
        m->fun->Get(String::NewSymbol("fd")),
        Boolean::New(ev->write)
    };
    m->fun->Call(m->recv, 2, argv); // event_cb
}

Handle<Value> NginxEvent::UpdateTimer(const Arguments& args) {
    ngx_http_request_t  *r;
    int64_t             timeout_ms;

    HandleScope scope;
    timeout_ms = args[0]->IntegerValue();

    Local<Value> request = args.Callee()->Get(String::NewSymbol("request"));
    r = static_cast<ngx_http_request_t*>(
            Local<External>::Cast(request)->Value());
    
    printf("timer update, %ld\n", static_cast<long>(timeout_ms));

    if (r->connection->write->timer_set) {
        ngx_del_timer(r->connection->write);
    }

    ngx_add_timer(r->connection->write, timeout_ms);

    r->write_event_handler = Ngxv8::TimeoutHandler;

    return Undefined();
}

Handle<Value> NginxEvent::RegisterFd(const Arguments& args) {
    int32_t             fd, what;
    ngx_http_request_t  *r;
    ngx_connection_t    *c;
    method_t            *m;

    HandleScope scope;

    Local<Value> request = args.Callee()->Get(String::NewSymbol("request"));
    r = static_cast<ngx_http_request_t*>(
            Local<External>::Cast(request)->Value());

    fd = args[0]->Int32Value();
    what = args[1]->Int32Value();

    if (args[2]->IsUndefined()) {

        m = static_cast<method_t*>(ngx_pcalloc(r->pool, sizeof(method_t)));
        Local<Object> recv = Local<Object>::Cast(args.Holder());
        Local<Function> event_cb_fun = Local<Function>::Cast(args[3]);
        event_cb_fun->Set(String::NewSymbol("fd"), Int32::New(fd));

        m->recv = Persistent<Object>::New(recv);
        m->fun = Persistent<Function>::New(event_cb_fun);

        c = ngx_get_connection(fd, r->connection->log);
        Handle<External> conn = External::New(c);

        c->data = m;
        c->read->handler = NginxEvent::IOHandler;
        c->write->handler = NginxEvent::IOHandler;

        // ???
        c->number = ngx_atomic_fetch_add(ngx_connection_counter, 1);

        if (ngx_add_conn(c) == NGX_ERROR) {
            return Integer::New(NGX_ERROR);
        }

        printf("Connected\n");

        return conn;
    }

    //Handle<External> conn = Handle<External>::Cast(args[2]);
    //c = static_cast<ngx_connection_t*>(Handle<External>::Cast(conn)->Value());
    //return conn;

    return args[2];
}

Handle<Value> NginxRequest::IO(const Arguments& args) {
    ngx_http_v8_loc_conf_t  *v8lcf;
    ngx_http_request_t      *r;
    ngx_http_v8_ctx_t       *ctx;

    HandleScope scope;
    Local<Object> self = args.This();
    Local<Function> init = Local<Function>::Cast(args[0]);
    Local<Function> post_fun = Local<Function>::Cast(args[1]);
    
    r = static_cast<ngx_http_request_t*>(Ngxv8::Unwrap(self, 0));
    v8lcf = static_cast<ngx_http_v8_loc_conf_t*>(
        ngx_http_get_module_loc_conf(r, ngx_http_v8_module));
    ctx = static_cast<ngx_http_v8_ctx_t*>(
        ngx_http_get_module_ctx(r, ngx_http_v8_module));
    ctx->next = static_cast<function_t*>(
        ngx_pcalloc(r->pool, sizeof(function_t)));
    ctx->next->fun = Persistent<Function>::New(post_fun);
    ctx->next->fun.MakeWeak(NULL, &Ngxv8::DisposeHandle);

    Local<External> request = External::New(r);
    Local<Function> update_timer = v8lcf->evt_update_timer->GetFunction();
    Local<Function> register_fd = v8lcf->evt_register_fd->GetFunction();
    update_timer->Set(String::NewSymbol("request"), request);
    register_fd->Set(String::NewSymbol("request"), request);

    Handle<Value> argv[3] = { v8lcf->context->Global(), update_timer, register_fd };
    init->Call(v8lcf->context->Global(), 3, argv);

    //ngx_add_event(rev, NGX_READ_EVENT, NGX_CLEAR_EVENT);

    /*if (ngx_handle_read_event(rev, 0) != NGX_OK) {
        return Integer::New(500);
    }*/
    
    return Integer::New(NGX_AGAIN);
}

Handle<Value> NginxRequest::ReadBody(const Arguments& args) {
    ngx_http_request_t *r;
    ngx_http_v8_ctx_t  *ctx;

    HandleScope scope;
    Handle<Object> self = args.This();
    Handle<Function> post_fun = Handle<Function>::Cast(args[0]);

    r = static_cast<ngx_http_request_t*>(Ngxv8::Unwrap(self, 0));
    ctx = static_cast<ngx_http_v8_ctx_t*>(
        ngx_http_get_module_ctx(r, ngx_http_v8_module));
    ctx->next = static_cast<function_t*>(
        ngx_pcalloc(r->pool, sizeof(function_t)));
    ctx->next->fun = Persistent<Function>::New(post_fun);
    // TODO: dispose handle when request finished instead of depending on gc
    ctx->next->fun.MakeWeak(NULL, &Ngxv8::DisposeHandle);

    r->request_body_in_single_buf = 1;
    r->request_body_in_persistent_file = 1;
    r->request_body_in_clean_file = 1;

    return Integer::New(ngx_http_read_client_request_body(r, Ngxv8::HandleRequest));
}

Handle<Value> NginxRequest::SendFile(const Arguments& args) {
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

    r = static_cast<ngx_http_request_t*>(Ngxv8::Unwrap(self, 0));
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

Handle<Value> NginxRequest::SetTimeout(const Arguments& args) {
    ngx_http_request_t *r;
    ngx_http_v8_ctx_t  *ctx;
    ngx_msec_t         timeout;

    HandleScope scope;
    Handle<Object> self = args.This();
    Handle<Function> post_fun = Handle<Function>::Cast(args[0]);
    timeout = args[1]->Int32Value();;

    r = static_cast<ngx_http_request_t*>(Ngxv8::Unwrap(self, 0));
    ctx = static_cast<ngx_http_v8_ctx_t*>(
        ngx_http_get_module_ctx(r, ngx_http_v8_module));
    ctx->next = static_cast<function_t*>(
        ngx_pcalloc(r->pool, sizeof(function_t)));
    ctx->next->fun = Persistent<Function>::New(post_fun);
    ctx->next->fun.MakeWeak(NULL, &Ngxv8::DisposeHandle);

    ngx_add_timer(r->connection->write, timeout);

    r->write_event_handler = Ngxv8::TimeoutHandler;

    return Integer::New(r->connection->write->timer.key);
}

Handle<Value> NginxRequest::HandShake(const Arguments& args) {
    ngx_http_request_t      *r;
    ngx_http_v8_loc_conf_t  *v8lcf;
    ngx_http_v8_ctx_t       *ctx;

    HandleScope scope;
    Local<Object> self = args.This();
    Local<Function> recv_fun = Local<Function>::Cast(args[0]);
    Local<Function> conn_fun = Local<Function>::Cast(args[1]);
    Local<Function> disconn_fun = Local<Function>::Cast(args[2]);

    r = static_cast<ngx_http_request_t*>(Ngxv8::Unwrap(self, 0));
    v8lcf = static_cast<ngx_http_v8_loc_conf_t*>(
        ngx_http_get_module_loc_conf(r, ngx_http_v8_module));
    ctx = static_cast<ngx_http_v8_ctx_t*>(
        ngx_http_get_module_ctx(r, ngx_http_v8_module));
    ctx->next = static_cast<function_t*>(
        ngx_pcalloc(r->pool, sizeof(function_t)));

    ctx->next->fun = Persistent<Function>::New(recv_fun);
    ctx->next->fun.MakeWeak(NULL, &Ngxv8::DisposeHandle);

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

/*Handle<Value> NginxRequest::Upstream(const Arguments& args) {
    return Proxy::New(args);
}*/

// --- Request Properties ---

Handle<Value> NginxRequest::GetUri(Local<String> name,
                                   const AccessorInfo& info) {
    ngx_http_request_t *r;

    r = static_cast<ngx_http_request_t*>(Ngxv8::Unwrap(info.Holder(), 0));

    return String::New(ptr_cast<const char*>(r->uri.data), r->uri.len);
}

Handle<Value> NginxRequest::GetMethod(Local<String> name,
                                      const AccessorInfo& info) {
    ngx_http_request_t *r;

    r = static_cast<ngx_http_request_t*>(Ngxv8::Unwrap(info.Holder(), 0));

    return String::New(ptr_cast<const char*>(r->method_name.data),
                       r->method_name.len);
}

Handle<Value> NginxRequest::GetUserAgent(Local<String> name,
                                         const AccessorInfo& info) {
    ngx_http_request_t *r;
    ngx_str_t          ua;

    r = static_cast<ngx_http_request_t*>(Ngxv8::Unwrap(info.Holder(), 0));
    ua = r->headers_in.user_agent->value;

    return String::New(ptr_cast<const char*>(ua.data), ua.len);
}

Handle<Value> NginxRequest::GetArgs(Local<String> name,
                                    const AccessorInfo& info) {
    ngx_http_request_t *r;

    r = static_cast<ngx_http_request_t*>(Ngxv8::Unwrap(info.Holder(), 0));

    return String::New(ptr_cast<const char*>(r->args.data), r->args.len);
}

Handle<Value> NginxRequest::GetBodyBuffer(Local<String> name,
                                          const AccessorInfo& info) {
    ngx_http_request_t *r;
    size_t             len;

    r = static_cast<ngx_http_request_t *>(Ngxv8::Unwrap(info.Holder(), 0));
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

Handle<Value> NginxRequest::GetBodyFileOrBuffer(Local<String> name,
                                                const AccessorInfo& info) {
    ngx_http_request_t  *r;
    char                *data;
    int                 fd;
    off_t               len;

    r = static_cast<ngx_http_request_t*>(Ngxv8::Unwrap(info.Holder(), 0));

    if (r->request_body == NULL
        || r->request_body->temp_file == NULL) {
        return NginxRequest::GetBodyBuffer(name, info);
    }

    fd = r->request_body->temp_file->file.fd;
    len = r->headers_in.content_length_n;

    data = static_cast<char*>(mmap(NULL, len, PROT_READ, MAP_PRIVATE, fd, 0));

    HandleScope scope;
    Local<String> b = String::New(data, len);
    munmap(data, len);

    return scope.Close(b);
}

void NginxRequest::SetBodyBuffer(Local<String> name,
                                 Local<Value> val,
                                 const AccessorInfo& info) {
    printf("---\n");
    ngx_http_request_t  *r;
    u_char             *p;
    int                len;
    
    HandleScope scope;
    r = static_cast<ngx_http_request_t*>(Ngxv8::Unwrap(info.Holder(), 0));
    Local<String> value = Local<String>::Cast(val);
    printf("---1\n");

    len = value->Utf8Length();
    p = static_cast<u_char*>(ngx_pnalloc(r->pool, len));
    value->WriteUtf8(ptr_cast<char*>(p), len);
    printf("---2\n");

    //printf("%d\n", r->request_body == NULL);
    r->request_body->bufs->buf->pos = p;
    r->request_body->bufs->buf->last = p + len;
    r->request_body->temp_file = NULL;
    printf("---3\n");
}
/*
void NginxResponse::SetRespContentType(Local<String> name,
                                       Local<Value> val,
                                       const AccessorInfo& info) {
    ngx_http_request_t *r;
    u_char             *p;
    int                len;
   
    HandleScope scope;
    r = static_cast<ngx_http_request_t*>(Ngxv8::Unwrap(info.Holder(), 0));
    Local<String> value = Local<String>::Cast(val);

    len = value->Utf8Length();
    p = static_cast<u_char*>(ngx_pnalloc(r->pool, len));
    value->WriteUtf8(ptr_cast<char*>(p), len);

    r->headers_out.content_type.data = p;
    r->headers_out.content_type.len = len;
}
*/
Handle<Value> NginxRequest::GetHeader(Local<String> name,
                                      const AccessorInfo& info) {
    ngx_http_request_t *r;
    ngx_http_v8_ctx_t  *ctx;
    ngx_list_part_t    *part;
    ngx_table_elt_t    *h;
    unsigned int       i;

    HandleScope scope;
    Local<Object> result = Object::New();

    r = static_cast<ngx_http_request_t*>(Ngxv8::Unwrap(info.Holder(), 0));
    ctx = static_cast<ngx_http_v8_ctx_t*>(
        ngx_http_get_module_ctx(r, ngx_http_v8_module));

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
    ctx->headers.MakeWeak(NULL, &Ngxv8::DisposeHandle);

    return scope.Close(result);
}

Handle<Value> NginxRequest::GetRealPath(Local<String> name,
                                        const AccessorInfo& info) {
    ngx_http_request_t  *r;
    u_char              *last;
    size_t              root;
    ngx_str_t           path;

    HandleScope scope;
    Local<Object> self = info.Holder();
    r = static_cast<ngx_http_request_t*>(Ngxv8::Unwrap(self, 0));

    last = ngx_http_map_uri_to_path(r, &path, &root, 0);
    path.len = last - path.data;

    return String::New(ptr_cast<const char*>(path.data), path.len);
}



Handle<Value> NginxResponse::New(const Arguments& args) {
    HandleScope scope;
    Local<Object> self = args.This();
    self->SetInternalField(0, Local<External>::Cast(args[0]));
    return scope.Close(self);
}

Handle<Value> NginxResponse::Write(const Arguments& args) {
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

    r = static_cast<ngx_http_request_t*>(Ngxv8::Unwrap(self, 0));
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

Handle<Value> NginxResponse::AddResponseHeader(const Arguments& args) {
    ngx_http_request_t  *r;
    ngx_table_elt_t     *header;
    u_char              *contentLength;
    size_t              len;

    HandleScope scope;
    Local<Object> self = args.This();
    String::AsciiValue key(args[0]);
    String::AsciiValue value(args[1]);
    r = static_cast<ngx_http_request_t*>(Ngxv8::Unwrap(self, 0));
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

// --- Response Properties ---

Handle<Value> NginxResponse::GetRespContentType(Local<String> name,
                                                const AccessorInfo& info) {
    ngx_http_request_t *r = static_cast<ngx_http_request_t*>(Ngxv8::Unwrap(info.Holder(), 0));
    return String::New(ptr_cast<const char*>(r->headers_out.content_type.data),
        r->headers_out.content_type.len);
}

void NginxResponse::SetRespContentType(Local<String> name,
                                       Local<Value> val,
                                       const AccessorInfo& info) {
    ngx_http_request_t *r;
    u_char             *p;
    int                len;
   
    HandleScope scope;
    r = static_cast<ngx_http_request_t*>(Ngxv8::Unwrap(info.Holder(), 0));
    Local<String> value = Local<String>::Cast(val);

    len = value->Utf8Length();
    p = static_cast<u_char*>(ngx_pnalloc(r->pool, len));
    value->WriteUtf8(ptr_cast<char*>(p), len);

    r->headers_out.content_type.data = p;
    r->headers_out.content_type.len = len;
}

static ngx_command_t  ngx_http_v8_commands[] = {

    { ngx_string("v8"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        Ngxv8::V8,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL },

    /*{ ngx_string("v8filter"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        Ngxv8::V8Filter,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL },*/

    { ngx_string("v8com"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
        Ngxv8::V8Com,
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
    //Ngxv8::FilterInit,                   /* postconfiguration */
    NULL,

    Ngxv8::CreateMainConf,               /* create main configuration */
    NULL,                                /* init main configuration */

    NULL,                                /* create server configuration */
    NULL,                                /* merge server configuration */

    Ngxv8::CreateLocConf,                /* create location configuration */
    Ngxv8::MergeLocConf                  /* merge location configuration */

};

ngx_module_t  ngx_http_v8_module = {
    NGX_MODULE_V1,
    &ngx_http_v8_module_ctx,       /* module context */
    ngx_http_v8_commands,          /* module directives */
    NGX_HTTP_MODULE,               /* module type */
    NULL,                          /* init master */
    NULL,                          /* init module */
    Ngxv8::InitProcess,            /* init process */
    NULL,                          /* init thread */
    NULL,                          /* exit thread */
    NULL,                          /* exit process */
    NULL,                          /* exit master */
    NGX_MODULE_V1_PADDING
};

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

/*ngx_int_t Ngxv8::FilterInit(ngx_conf_t *cf) {
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = Ngxv8::HeaderFilter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = Ngxv8::BodyFilter;

    return NGX_OK;
}*/

void* Ngxv8::CreateMainConf(ngx_conf_t *cf) {
    ngx_http_v8_main_conf_t *conf;

    conf = static_cast<ngx_http_v8_main_conf_t*>(
        ngx_pcalloc(cf->pool, sizeof(ngx_http_v8_main_conf_t)));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->agent_port = NGX_CONF_UNSET_UINT;

    return conf;
}

void* Ngxv8::CreateLocConf(ngx_conf_t *cf) {
    ngx_http_v8_loc_conf_t *conf;

    conf = static_cast<ngx_http_v8_loc_conf_t*>(
        ngx_pcalloc(cf->pool, sizeof(ngx_http_v8_loc_conf_t)));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    return conf;
}

char* Ngxv8::MergeLocConf(ngx_conf_t *cf, void *parent, void *child) {
    return NGX_CONF_OK;
}

char* Ngxv8::V8(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_v8_loc_conf_t      *v8lcf;
    ngx_http_core_loc_conf_t    *clcf;
    ngx_str_t                   *value;
    const char                  *filename;

    v8lcf = static_cast<ngx_http_v8_loc_conf_t*>(conf);
    value = static_cast<ngx_str_t*>(cf->args->elts);

    clcf = static_cast<ngx_http_core_loc_conf_t *>(
        ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module));
    clcf->handler = Ngxv8::V8Handler;

    HandleScope scope;
    if (v8lcf->context.IsEmpty()) {
        //V8::SetFlagsFromString("--expose_debug_as debug", strlen("--expose_debug_as debug"));
        Local<ObjectTemplate> global = ObjectTemplate::New();
        Local<ObjectTemplate> components = ObjectTemplate::New();
        global->Set(String::NewSymbol("log"), FunctionTemplate::New(Ngxv8::Log));
        if (v8lcf->classes.IsEmpty()) {
            v8lcf->classes = Persistent<ObjectTemplate>::New(ObjectTemplate::New());
        }
        components->Set(String::NewSymbol("classes"), v8lcf->classes);
        //components->Set(String::New("interfaces"), v8lcf->interfaces);
        //components->Set(String::New("lookup"), FunctionTemplate::New(Lookup));
        global->Set(String::NewSymbol("Components"), components);

        v8lcf->request_tmpl = Persistent<FunctionTemplate>::New(Ngxv8::MakeRequestTemplate());
        global->Set(String::NewSymbol("NginxRequest"), v8lcf->request_tmpl);

        v8lcf->response_tmpl = Persistent<FunctionTemplate>::New(Ngxv8::MakeResponseTemplate());
        global->Set(String::NewSymbol("NginxResponse"), v8lcf->response_tmpl);

        v8lcf->evt_update_timer = Persistent<FunctionTemplate>::New(
                FunctionTemplate::New(NginxEvent::UpdateTimer));
        v8lcf->evt_register_fd = Persistent<FunctionTemplate>::New(
                FunctionTemplate::New(NginxEvent::RegisterFd));

        const char *extensionNames[] = { "v8/gc" };
        ExtensionConfiguration extensions(sizeof(extensionNames)/sizeof(extensionNames[0]),
                                          extensionNames);
        //v8lcf->context = Context::New(NULL, global);
        v8lcf->context = Context::New(&extensions, global);
    }

    Context::Scope context_scope(v8lcf->context);
    //V8::SetGlobalGCEpilogueCallback(GCCall);
    filename = ptr_cast<const char*>(value[1].data);
    if (Ngxv8::ExecuteScript_(filename) == -1) {
        return static_cast<char*>(NGX_CONF_ERROR);
    }

    if (v8lcf->process.IsEmpty() &&
        v8lcf->context->Global()->Has(String::NewSymbol("process"))) {
        Local<Value> process_val = v8lcf->context->Global()->Get(String::NewSymbol("process"));
        Local<Function> process_fun = Local<Function>::Cast(process_val);
        v8lcf->process = Persistent<Function>::New(process_fun);
    }

    return NGX_CONF_OK;
}

/*char* Ngxv8::V8Filter(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_v8_loc_conf_t      *v8lcf;
    //ngx_http_core_loc_conf_t    *clcf;
    ngx_str_t                   *value;
    const char                  *filename;

    v8lcf = static_cast<ngx_http_v8_loc_conf_t *>(conf);
    value = static_cast<ngx_str_t *>(cf->args->elts);

    HandleScope scope;
    if (v8lcf->context.IsEmpty()) {
        //V8::SetFlagsFromString("--expose_debug_as debug", strlen("--expose_debug_as debug"));
        Local<ObjectTemplate> global = ObjectTemplate::New();
        Local<ObjectTemplate> components = ObjectTemplate::New();
        global->Set(String::NewSymbol("log"), FunctionTemplate::New(Ngxv8::Log));
        if (v8lcf->classes.IsEmpty()) {
            v8lcf->classes = Persistent<ObjectTemplate>::New(ObjectTemplate::New());
        }
        components->Set(String::NewSymbol("classes"), v8lcf->classes);
        //components->Set(String::New("interfaces"), v8lcf->interfaces);
        //components->Set(String::New("lookup"), FunctionTemplate::New(Lookup));
        global->Set(String::NewSymbol("Components"), components);

        v8lcf->request_tmpl = Persistent<FunctionTemplate>::New(Ngxv8::MakeRequestTemplate());
        global->Set(String::NewSymbol("NginxRequest"), v8lcf->request_tmpl);

        v8lcf->response_tmpl = Persistent<FunctionTemplate>::New(Ngxv8::MakeResponseTemplate());
        global->Set(String::NewSymbol("NginxResponse"), v8lcf->response_tmpl);

        const char *extensionNames[] = { "v8/gc" };
        ExtensionConfiguration extensions(sizeof(extensionNames)/sizeof(extensionNames[0]),
                                          extensionNames);
        //v8lcf->context = Context::New(NULL, global);
        v8lcf->context = Context::New(&extensions, global);
    }

    Context::Scope context_scope(v8lcf->context);
    //V8::SetGlobalGCEpilogueCallback(GCCall);
    filename = ptr_cast<const char*>(value[1].data);
    if (Ngxv8::ExecuteScript_(filename) == -1) {
        return static_cast<char*>(NGX_CONF_ERROR);
    }

    if (v8lcf->process.IsEmpty() &&
        v8lcf->context->Global()->Has(String::NewSymbol("process"))) {
        Local<Value> process_val = v8lcf->context->Global()->Get(String::NewSymbol("process"));
        Local<Function> process_fun = Local<Function>::Cast(process_val);
        v8lcf->process = Persistent<Function>::New(process_fun);
    }

    v8lcf->filter_enabled = 1;

    return NGX_CONF_OK;
}*/

char* Ngxv8::V8Com(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
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

ngx_int_t Ngxv8::InitProcess(ngx_cycle_t *cycle)
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

/*ngx_int_t Ngxv8::HeaderFilter(ngx_http_request_t *r) {
    return ngx_http_next_header_filter(r);
}*/

/*ngx_int_t Ngxv8::BodyFilter(ngx_http_request_t *r, ngx_chain_t *in) {

    ngx_http_v8_loc_conf_t  *v8lcf;
    ngx_http_v8_ctx_t       *ctx;
    ngx_chain_t             *il, *cl;
    int                     size;

    if (in == NULL || r->header_only) {
        return ngx_http_next_body_filter(r, in);
    }

    v8lcf = static_cast<ngx_http_v8_loc_conf_t*>(
        ngx_http_get_module_loc_conf(r, ngx_http_v8_module));

    if (!v8lcf->filter_enabled) {
        return ngx_http_next_body_filter(r, in);
    }

    ctx = Ngxv8::GetContext_(r);
    if (ctx->in == NULL) {
        ctx->in = static_cast<brigade_t*>(ngx_pcalloc(r->pool, sizeof(brigade_t)));
        ctx->in->size = 0;
        ctx->in->head = ctx->in->tail = NULL;
    }
    
    cl = in;

    while (1) {
        size = ngx_buf_size(cl->buf);
        //printf("|%d:%d:%d", (int)cl->buf->pos, size, cl->buf->last_buf);
        ctx->in->size += size;

        il = ngx_alloc_chain_link(r->pool);
        il->buf = static_cast<ngx_buf_t*>(ngx_pcalloc(r->pool, sizeof(ngx_buf_t)));
        il->buf->memory = 1;
        il->buf->pos = static_cast<u_char*>(ngx_pnalloc(r->pool, size));
        ngx_memcpy(il->buf->pos, cl->buf->pos, size);
        il->buf->last = il->buf->pos + size;
        il->buf->last_buf = cl->buf->last_buf;
        
        if (ctx->in->head == NULL) {
            ctx->in->head = ctx->in->tail = il;
        } else {
            ctx->in->tail->next = il;
            ctx->in->tail = il;
        }

        if (cl->next == NULL) {
            break;
        }

        cl = cl->next;
    }
    //printf("\n");

    if (!cl->buf->last_buf) {
        return ngx_http_next_body_filter(r, in);
    }

    cl = ctx->in->head;

    char *p, *h;
    p = static_cast<char*>(ngx_pnalloc(r->pool, ctx->in->size));
    h = p;

    while (1) {
        int size;
        size = ngx_buf_size(cl->buf);
        //printf("%d:%d:%d|", (int)cl->buf->pos, size, cl->buf->last_buf);
        ngx_memcpy(h, cl->buf->pos, size);
        h += size;
        
        if (cl->buf->last_buf) {
            break;
        }
        cl = cl->next;
    }
    //printf("\n");
    Context::Scope context_scope(v8lcf->context);
    HandleScope scope;
    Local<String> s = String::New(p, ctx->in->size);
    String::Utf8Value u(s);
    Local<Object> request_obj = Ngxv8::WrapRequest(v8lcf, r);
    Handle<Value> argv[2] = { request_obj, s };
    printf("s=%d\n", ctx->in->size);
    printf("l=%d\n", s->Length());
    printf("u=%d\n", s->Utf8Length());
    printf("u2=%d\n", u.length());
    printf("x=%d\n", sizeof(unsigned char));
    printf("x=%d\n", sizeof(uint16_t));

    Handle<Value> result = v8lcf->process->Call(v8lcf->context->Global(), 2, argv);
    return ngx_http_next_body_filter(r, in);
}*/

ngx_int_t Ngxv8::V8Handler(ngx_http_request_t *r) {
    Ngxv8::HandleRequest(r);
    return NGX_DONE;
}

void Ngxv8::HandleRequest(ngx_http_request_t *r) {
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

    v8lcf = static_cast<ngx_http_v8_loc_conf_t*>(
        ngx_http_get_module_loc_conf(r, ngx_http_v8_module));

    if (ctx->next == NULL) {
        fun = v8lcf->process;
    } else {
        fun = ctx->next->fun;
        ctx->next = NULL;
    }
    
    ngx_http_clean_header(r);

    rc = Ngxv8::CallHandler(r, v8lcf, fun);

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

    printf("finalizeing\n");
    ngx_http_finalize_request(r, rc);
}

ngx_int_t Ngxv8::CallHandler(ngx_http_request_t *r,
                             ngx_http_v8_loc_conf_t *v8lcf,
                             Persistent<Function> fun) {
    ngx_connection_t *c;

    c = r->connection;

    Context::Scope context_scope(v8lcf->context);
    HandleScope scope;

    Local<Object> request_obj = Ngxv8::WrapRequest(v8lcf, r);
    Local<Object> response_obj = Ngxv8::WrapResponse(v8lcf, r);
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

    return static_cast<ngx_int_t>(result->Int32Value());
}

void Ngxv8::TimeoutHandler(ngx_http_request_t *r) {
    ngx_event_t  *wev;

    wev = r->connection->write;

    if (wev->timedout) {
        wev->timedout = 0;
        Ngxv8::HandleRequest(r);
        return;
    }

    if (ngx_handle_write_event(wev, 0) != NGX_OK) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
    }
}

Handle<Value> Ngxv8::ReadFile_(const char* filename) {
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

int Ngxv8::ExecuteScript_(const char* file) {
    HandleScope scope;

    Handle<Value> source = Ngxv8::ReadFile_(file);
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

ngx_http_v8_ctx_t* Ngxv8::GetContext_(ngx_http_request_t *r) {
    ngx_http_v8_ctx_t *ctx;

    ctx = static_cast<ngx_http_v8_ctx_t*>(
            ngx_http_get_module_ctx(r, ngx_http_v8_module));

    if (ctx == NULL) {
        ctx = static_cast<ngx_http_v8_ctx_t*>(
                ngx_pcalloc(r->pool, sizeof(ngx_http_v8_ctx_t)));
        ctx->in = NULL;
        ctx->out = static_cast<brigade_t*>(ngx_palloc(r->pool, sizeof(brigade_t)));
        ctx->out->size = 0;
        ctx->out->head = ctx->out->tail = NULL;
        //ctx->filtered = 0;
        ngx_http_set_ctx(r, ctx, ngx_http_v8_module);
    }

    return ctx;
}


// -----------------------------------------------------------------------------
/*
class XHRExtension : public v8::Extension {
    public:
        XHRExtension() : v8::Extension("ngxv8/xhr", kSource) { }
        v8::Handle<v8::FunctionTemplate> GetNativeFunction(
                v8::Handle<v8::String> name);
        static v8::Handle<v8::Value> NewXHR(const v8::Arguments& args);
    private:
        static const char* kSource;
};

const char* XHRExtension::kSource = "native function xhr(request);";

v8::Handle<v8::FunctionTemplate> XHRExtension::GetNativeFunction(
        v8::Handle<v8::String> name) {
    return v8::FunctionTemplate::New(XHRExtension::NewXHR);
}

v8::Handle<v8::Value> XHRExtension::NewXHR(const v8::Arguments& args) {
    ngx_http_request_t *r;
    v8::HandleScope scope;
    v8::Local<v8::Value> field = v8::Local<v8::Object>::Cast(args[0])->GetInternalField(0);
    r = static_cast<ngx_http_request_t*>(v8::Local<v8::External>::Cast(field)->Value());
    v8::Local<v8::Object> self = v8::Object::New();
    return scope.Close(self);
}

static XHRExtension kXHRExtension;
v8::DeclareExtension kXHRExtensionDeclaration(&kXHRExtension);
*/

/*
Handle<Value> Proxy::New(const Arguments& args) {
    ngx_http_request_t      *r;
    ngx_http_upstream_t     *u;
    ngx_http_v8_ctx_t       *ctx;
    ngx_url_t                url;

    HandleScope scope;
    String::Utf8Value urlstr(args[0]);
    url.url.len = urlstr.length();
    url.url.data = ptr_cast<u_char*>(*urlstr);
    url.default_port = 80;
    url.uri_part = 1;
    url.no_resolve = 1;

    Local<Object> self = args.This();
    Local<Function> finish_fun = Local<Function>::Cast(args[1]);
    //Local<Function> abort_fun = Local<Function>::Cast(args[2]);

    r = static_cast<ngx_http_request_t*>(Ngxv8::Unwrap(self, 0));
    ctx = static_cast<ngx_http_v8_ctx_t*>(
        ngx_http_get_module_ctx(r, ngx_http_v8_module));
    ctx->next = static_cast<function_t*>(
        ngx_pcalloc(r->pool, sizeof(function_t)));

    ctx->next->fun = Persistent<Function>::New(finish_fun);
    ctx->next->fun.MakeWeak(NULL, &Ngxv8::DisposeHandle);

    u = static_cast<ngx_http_upstream_t*>(ngx_pcalloc(r->pool,
                        sizeof(ngx_http_upstream_t)));

    r->upstream = u;
    u->create_request = Proxy::CreateRequest;
    u->reinit_request = Proxy::ReinitRequest;
    u->process_header = Proxy::ProcessHeader;
    u->abort_request = Proxy::AbortRequest;
    u->finalize_request = Proxy::FinalizeRequest;

    u->conf = static_cast<ngx_http_upstream_conf_t*>(
            ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_conf_t)));
    //u->conf->upstream = Proxy::UpstreamAdd(r, &url, 0);

    ngx_http_upstream_init(r);

    return Integer::New(NGX_DONE);
}

ngx_int_t Proxy::CreateRequest(ngx_http_request_t *r) {
    printf("CreateRequest\n");
    ngx_buf_t   *b;
    ngx_chain_t *cl;

    b = ngx_create_temp_buf(r->pool, sizeof("a") - 1);
    if (b == NULL)
        return NGX_ERROR;

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL)
        return NGX_ERROR;

    cl->buf = b;
    r->upstream->request_bufs = cl;
    b->pos = ptr_cast<u_char*>(const_cast<char*>("a"));
    b->last = b->pos + sizeof("a") - 1;
    printf("/CreateRequest\n");

    return NGX_OK;
}

ngx_int_t Proxy::ReinitRequest(ngx_http_request_t *r) {
    printf("ReinitRequest\n");
    return 1;
}

ngx_int_t Proxy::ProcessHeader(ngx_http_request_t *r) {
    printf("ProcessHeader\n");
    ngx_http_upstream_t *u;

    u = r->upstream;

    switch (u->buffer.pos[0]) {
        case '?':
            r->header_only = 1;
            u->headers_in.status_n = 404;
            break;
        case ' ':
            u->buffer.pos++;
            u->headers_in.status_n = 200;
            break;
    }

    return NGX_OK;
}

void Proxy::AbortRequest(ngx_http_request_t *r) {
    printf("AbortRequest\n");
}

void Proxy::FinalizeRequest(ngx_http_request_t *r, ngx_int_t rc) {
    printf("FinalizeRequest\n");
}

ngx_http_upstream_srv_conf_t* Proxy::UpstreamAdd(ngx_http_request_t *r,
                                                 ngx_url_t *u,
                                                 ngx_uint_t flags) {
    ngx_http_upstream_server_t     *us;
    ngx_http_upstream_srv_conf_t   *uscf, **uscfp;
    ngx_http_upstream_main_conf_t  *umcf;

    umcf = static_cast<ngx_http_upstream_main_conf_t*>(
            ngx_http_get_module_main_conf(r, ngx_http_upstream_module));

    uscfp = static_cast<ngx_http_upstream_srv_conf_t**>(umcf->upstreams.elts);

    uscf = static_cast<ngx_http_upstream_srv_conf_t*>(
            ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_srv_conf_t)));
    uscf->flags = flags;
    uscf->host = u->host;
    uscf->port = u->port;
    uscf->default_port = u->default_port;

    if (u->naddrs == 1) {
        uscf->servers = ngx_array_create(r->pool, 1,
                sizeof(ngx_http_upstream_server_t));
        //if (uscf->servers == NULL) {
        //    return NGX_CONF_ERROR;
        //}

        us = static_cast<ngx_http_upstream_server_t*>(ngx_array_push(uscf->servers));
        //if (us == NULL) {
        //    return NGX_CONF_ERROR;
        //}

        ngx_memzero(us, sizeof(ngx_http_upstream_server_t));

        us->addrs = u->addrs;
        us->naddrs = u->naddrs;
    }

    uscfp = static_cast<ngx_http_upstream_srv_conf_t**>(ngx_array_push(&umcf->upstreams));
    if (uscfp == NULL) {
        return NULL;
    }

    *uscfp = uscf;

    return uscf;

}
*/
