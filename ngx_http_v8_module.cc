extern "C" {
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <nginx.h>

#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>
}
//#define V8_TARGET_ARCH_X64 1
#include <v8.h>
//#include <../src/v8.h>
#include <dlfcn.h>
#include <iostream>

using namespace std;
using namespace v8;

extern ngx_module_t  ngx_http_v8_module;

static char *ngx_http_v8(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_v8com(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void *ngx_http_v8_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_v8_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
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

/*typedef struct {
    int kq;
    int num_files;
    int markfd;
    const char **files;
    pthread_t *thr;
} poll_file_t;*/

typedef struct {
    Persistent<Context> context;
    Persistent<Function> process;
    Persistent<ObjectTemplate> classes;
    Persistent<ObjectTemplate> interfaces;
    Persistent<ObjectTemplate> request_tmpl;
    Persistent<ObjectTemplate> response_tmpl;
    //poll_file_t *poll_file;
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
    NULL,                          /* init process */
    NULL,                          /* init thread */
    NULL,                          /* exit thread */
    NULL,                          /* exit process */
    NULL,                          /* exit master */
    NGX_MODULE_V1_PADDING
};

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

static Handle<Value> GetBody(Local<String> name,
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

static Handle<Value> GetBodyFile(Local<String> name,
                      const AccessorInfo& info)
{
    ngx_http_request_t *r = static_cast<ngx_http_request_t*>(Unwrap(info.Holder(), 0));
    ngx_str_t *temp;

    if (r->request_body == NULL
        || r->request_body->temp_file == NULL) {
        return Undefined();
    }

    temp = &r->request_body->temp_file->file.name;
    return String::New(reinterpret_cast<const char*>(temp->data), temp->len);
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
    len = strlen(*name);
    r = static_cast<ngx_http_request_t *>(Unwrap(args.This(), 0));
    lowcase = static_cast<u_char *>(ngx_pnalloc(r->pool, len));
    p = reinterpret_cast<u_char *>(*name);
    hash = ngx_hash_strlow(lowcase, p, len);
    var.len = len;
    var.data = lowcase;
    vv = ngx_http_get_variable(r, &var, hash, 1);

    if (vv->not_found) {
        return Undefined();
    }
    return String::New(reinterpret_cast<const char *>(vv->data), vv->len);
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
    size_t len = strlen(*value);
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
    result->SetAccessor(String::NewSymbol("body"), GetBody);
    result->SetAccessor(String::NewSymbol("bodyFile"), GetBodyFile);
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
        cerr << *st_str << endl;
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (c->destroyed) {
        return NGX_DONE;
    }

    if (result->IsUndefined()) {
        return NGX_OK;
    }

    //internal::Heap::CollectAllGarbage(false);
    /*ngx_int_t x = static_cast<ngx_int_t>(result->Int32Value());
    printf("%d\n", x);
    return x;*/
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

    //printf("ngx_http_v8_handler_request\n");
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

    //printf("rc=%d\n", rc);

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
    //printf("ReadBody\n");
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

    //r->request_body_in_file_only = 1;
    r->request_body_in_persistent_file = 1;
    r->request_body_in_clean_file = 1;

    if (r->request_body_in_file_only) {
        r->request_body_file_log_level = 0;
    }

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

    len = strlen(*value);
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

    len = strlen(*key);
    header->key.len = len;
    header->key.data = static_cast<u_char*>(ngx_pnalloc(r->pool, len));
    ngx_memcpy(header->key.data, *key, len);

    len = strlen(*value);
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
    cout << (*value) << endl;
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

static Local<String> read_file(const char* filename) {
    FILE    *file;
    size_t  size;
    char    *chars;
   
    file = fopen(filename, "rb");

    if (file == NULL) {
        return String::New("");
    }

    fseek(file, 0, SEEK_END);
    size = ftell(file);
    rewind(file);

    chars = new char[size + 1];
    chars[size] = '\0';

    for (int i = 0; i < size;) {
        int read = fread(&chars[i], 1, size - i, file);
        i += read;
    }

    fclose(file);

    HandleScope scope;
    Local<String> result = String::New(chars, size);
    delete[] chars;

    return scope.Close(result);
}

static void execute_script(const char* file)
{
    HandleScope scope;

    Local<String> source = read_file(file);
    if (source->Length() == 0) {
        return;
    }

    Local<String> filename = String::New(file);
    Local<Script> script = Script::Compile(source, filename);

    TryCatch trycatch;
    Local<Value> result = script->Run();
    if (trycatch.HasCaught()) {
        Local<Value> st = trycatch.StackTrace();
        String::AsciiValue st_str(st);
        cerr << *st_str << endl;
    }

    scope.Close(result);
}

/*static int register_event(int kq, struct kevent *kev, const char *filename, bool read)
{
    int fd, i;

    for (i = 0; i < 3; i++) {
        if ((fd = open(filename, O_RDONLY)) > 0) {
            break;
        }
        printf("retry open\n");
        usleep(100000);
    }

    if (fd < 0) {
        return fd;
    }

    EV_SET(kev, fd, EVFILT_VNODE, EV_ADD, NOTE_RENAME, 0, const_cast<char*>(filename));
    kevent(kq, kev, 1, NULL, 0, NULL);
    if (read) {
        EV_SET(kev, fd, EVFILT_READ, EV_ADD, 0, 0, const_cast<char*>(filename));
        kevent(kq, kev, 1, NULL, 0, NULL);
    }

    printf("registered %s(%d)\n", filename, fd);

    return fd;
}

static void* poll_file(void *ctx)
{
    ngx_http_v8_loc_conf_t  *v8lcf;
    poll_file_t             *poll_file;
    const char              *filename;
    int                     i, j, n, fd;
    
    //poll_file = static_cast<poll_file_t*>(ctx);
    v8lcf = static_cast<ngx_http_v8_loc_conf_t*>(ctx);
    poll_file = v8lcf->poll_file;
    struct kevent kev[poll_file->num_files];
    int fds[poll_file->num_files];

    for (i = 0; i < poll_file->num_files; i++) {
        if ((fds[i] = register_event(poll_file->kq, &kev[i], poll_file->files[i], true)) < 0) {
            printf("first registration fail: %s\n", poll_file->files[i]);
            return NULL;
        }
        lseek(fds[i], 0, SEEK_END);
    }
    poll_file->markfd = fds[0];

    while (true) {
        n = kevent(poll_file->kq, NULL, 0, kev, poll_file->num_files, NULL);
        for (i = 0; i < n; i++) {
            if (!(kev[i].fflags & NOTE_RENAME)) {
                printf("reschedule\n");
                for (j = 0; j < poll_file->num_files; j++) {
                    close(fds[j]);
                }
                return NULL;
            }
            close(kev[i].ident);
            filename = static_cast<const char*>(kev[i].udata);
            printf("modify detected: %s\n", filename);
            
            //v8lcf->context = Context::New(NULL, v8lcf->global);
            Context::Scope context_scope(v8lcf->context);
            v8::Locker locker;
            execute_script(filename);
            v8::Unlocker unlocker;

            fd = register_event(poll_file->kq, &kev[i], filename, false);
            if (fd < 0) {
                printf("re-registration fail: %s\n", filename);
            }
        }
    }

    return NULL;
}*/

static char *
ngx_http_v8(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_v8_loc_conf_t      *v8lcf;
    ngx_http_core_loc_conf_t    *clcf;
    ngx_str_t                   *value;
    //poll_file_t                 *pf;
    const char                  *filename;

    v8lcf = static_cast<ngx_http_v8_loc_conf_t *>(conf);
    value = static_cast<ngx_str_t *>(cf->args->elts);

    clcf = static_cast<ngx_http_core_loc_conf_t *>(
        ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module));
    clcf->handler = ngx_http_v8_handler;

    HandleScope scope;
    if (v8lcf->context.IsEmpty()) {
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
    execute_script(filename);

    /*if (v8lcf->poll_file == NULL) {
        pf = new poll_file_t();
        pf->kq = kqueue();
        pf->thr = new pthread_t();
        pf->num_files = 1;
        pf->files = new const char*[1];
        pf->files[0] = filename;
        v8lcf->poll_file = pf;
        pthread_create(pf->thr, NULL, poll_file, v8lcf);
    } else {
        pf = v8lcf->poll_file;
        lseek(pf->markfd, 0, SEEK_SET);
        printf("wait for join\n");
        pthread_join(*pf->thr, NULL);
        printf("joined\n");
        pf->num_files += 1;
        const char **renew = new const char*[pf->num_files];
        // memcpy
        for (int i = 0; i < pf->num_files - 1; i++) {
            renew[i] = pf->files[i];
        }
        delete[] pf->files;
        renew[pf->num_files - 1] = filename;
        pf->files = renew;
        v8lcf->poll_file = pf;
        pthread_create(pf->thr, NULL, poll_file, v8lcf);
    }*/

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
    handle = dlopen(reinterpret_cast<const char*>(value[2].data), RTLD_LAZY);
    Handle<Template>(*createObject)();

    createObject = reinterpret_cast<Handle<Template> (*)()>(dlsym(handle, "createObject"));
    v8lcf->classes->Set(name, createObject());
    //dlclose(handle);

    return NGX_CONF_OK;
}

