const http = require('http');
const app = require('../api/_app');

const port = process.env.PORT || 3001;
http.createServer(app).listen(port, () => {
  console.log(`SVFIT backend listening on http://localhost:${port}`);
});
