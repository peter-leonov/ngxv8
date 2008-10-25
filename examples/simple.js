function process(request, response) {
    if (request.userAgent.indexOf('iPhone OS 2') != -1) {
        response.write('This is iPhone OS 2');
    } else {
        response.contentType = 'text/xml; charset=utf-8';
        response.write('<?xml version="1.0" encoding="utf-8"?><ngxv8/>');
    }
    return 200;
}
