const Cc = Components.classes;

const HDB = Cc['@v8com/tokyocabinet/HDB;1'];
const ClearSilver = Cc['@v8com/ClearSilver;1'];

const DB = '/Users/rykomats/hdb';
const TMPL = '/Users/rykomats/tmpl.html';

const FAMILY = '小松';
const MEMBERS = [
    ['亮介', 26],
    ['まる', 11]
];

function getCount() {
    var hdb = new HDB(DB)
    var count = parseInt(hdb.get('count'));
    hdb.put('count', ++count);
    hdb.close();
    return count;
}

function process(request, response) {
    var cs = new ClearSilver(TMPL);
    cs.set('family', FAMILY);
    cs.set('count', getCount());
    cs.set('today', new Date());
    for (var i in MEMBERS) {
        cs.set('child.' + i + '.name', MEMBERS[i][0]);
        cs.set('child.' + i +  '.age', MEMBERS[i][1]);
    }
    cs.render(function(d) {
        response.write(d);
    });
    cs.destroy();
    return 200;
}
