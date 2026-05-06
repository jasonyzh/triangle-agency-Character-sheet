const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const cors = require('cors');

const app = express();
app.use(cors());

const PORT = 3333;

app.use(express.static(path.join(__dirname, 'public')));
app.use(bodyParser.json());

require('./db/init');

app.use(require('./routes/options'));
app.use(require('./routes/auth'));
app.use(require('./routes/admin'));
app.use(require('./routes/monitor'));
app.use(require('./routes/characters'));
app.use(require('./routes/records'));
app.use(require('./routes/shares'));
app.use(require('./routes/items'));
app.use(require('./routes/documents'));
app.use(require('./routes/messages'));
app.use(require('./routes/missions'));
app.use(require('./routes/mail'));
app.use(require('./routes/manager-inbox'));
app.use(require('./routes/branches'));
app.use(require('./routes/siphon'));
app.use(require('./routes/anomaly-templates'));

app.get('/', (req, res) => res.redirect('/login.html'));

app.listen(PORT, () => {
    console.log(`服务器运行中: http://localhost:${PORT}`);
    console.log(`数据目录: ${path.join(__dirname, 'data')}`);
});
