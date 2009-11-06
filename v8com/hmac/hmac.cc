#include <openssl/hmac.h>
#include <string>
#include "hmac.h"

using namespace std;
using namespace v8;

namespace hmac {

static Handle<Value> Sha1(const Arguments& args)
{
    HandleScope scope;
    String::AsciiValue key(args[0]);
    String::Utf8Value d(args[1]);
    const char *_key = *key;
    const unsigned char *_d = reinterpret_cast<const unsigned char *>(*d);
    unsigned char *md = static_cast<unsigned char *>(malloc(EVP_MAX_MD_SIZE));
    unsigned int md_len;
    HMAC(EVP_sha1(), _key, strlen(_key), _d, strlen(*d), md, &md_len);
    free(md);
    //Handle<String> ret = String::New(reinterpret_cast<const char *>(md), md_len);
    int i = 0;
    Handle<Array> result = Array::New(md_len);
    for (i; i < md_len; i++) {
        result->Set(Number::New(i), Number::New(md[i]));
    }
    return scope.Close(result);
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
    hmac->Set(String::New("sha1"), FunctionTemplate::New(hmac::Sha1));
    return handle_scope.Close(hmac);
}

}
