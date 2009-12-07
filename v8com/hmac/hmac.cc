#include <openssl/hmac.h>
#include <string>
#include "hmac.h"

using namespace std;
using namespace v8;

namespace hmac {

static Handle<Value> New(const EVP_MD *evp, const Arguments& args)
{
    unsigned int    i;
    unsigned char   md[EVP_MAX_MD_SIZE];
    unsigned int    md_len;

    HandleScope scope;

    String::AsciiValue key(args[0]);
    String::Utf8Value d(args[1]);
    HMAC(evp, *key, key.length(),
         reinterpret_cast<const unsigned char*>(*d), d.length(), md, &md_len);

    Handle<Array> result = Array::New(md_len);
    for (i = 0; i < md_len; i++) {
        result->Set(Number::New(i), Number::New(md[i]));
    }

    return scope.Close(result);
}

static Handle<Value> NewSha1(const Arguments& args)
{
    return New(EVP_sha1(), args);
}

static Handle<Value> NewMd5(const Arguments& args)
{
    return New(EVP_md5(), args);
}

} // end namespace hmac

extern "C" {
    
Handle<String> getName()
{
    HandleScope scope;
    Handle<String> name = String::New("@v8com/hmac;1");
    return scope.Close(name);
}

Handle<ObjectTemplate> createObject()
{
    HandleScope handle_scope;
    Handle<ObjectTemplate> hmac = ObjectTemplate::New();
    hmac->Set(String::New("sha1"), FunctionTemplate::New(hmac::NewSha1));
    hmac->Set(String::New("md5"), FunctionTemplate::New(hmac::NewMd5));
    return handle_scope.Close(hmac);
}

}
