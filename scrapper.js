const ChangesStream = require('changes-stream');
 
const db = 'https://replicate.npmjs.com';

var changes = new ChangesStream({
   db: db,
   include_docs: true,
   since: 'now'
});

changes.on('data', function(change) {
    try {
        if (!change.deleted) {
            console.log(change.id);
        }
    } catch (err) {
        return 0
    }
    
})