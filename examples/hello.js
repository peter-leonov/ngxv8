const Cc = Components.classes;
const TC = Cc['@v8com/tokyocabinet;1'];

function bound(request, C) {
    var o = new C();
    return request.bind(o.dispose, o);
}

function doGet(request, response) {
    var u = TC.util;
    var tmpl = bound(request, TC.TMPL);
    var vars = bound(request, u.TCMAP);
    var elements = bound(request, u.TCLIST);
    forEach(range(0, 10), function(i) {
        var r = bound(request, u.TCMAP);
        r.put('id', i);
        r.put('name', 'name:' + i);
        elements.pushMap(r);
    });
    tmpl.load('tmpl/hello.tmpl');
    vars.putList('elements', elements);
    response.write(tmpl.dump(vars));
    return 200;
}

process = doGet;
