#include <v8.h>

using namespace v8;

extern "C" {
    Handle<String> getName();
    Handle<FunctionTemplate> createObject();
}
