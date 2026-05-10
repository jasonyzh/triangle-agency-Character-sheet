const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const cors = require('cors');
const http = require('http');
const { Server } = require('socket.io');
const jwt = require('jsonwebtoken');
const { JWT_SECRET } = require('./constants');

const app = express();
app.use(cors());

const PORT = 3333;

const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

// JWT auth middleware for Socket.IO
io.use((socket, next) => {
    const token = socket.handshake.auth.token;
    if (!token) return next(new Error('未授权'));
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        socket.userId = decoded.userId;
        socket.userRole = decoded.role || 0;
        next();
    } catch(e) {
        next(new Error('令牌无效'));
    }
});

app.use(express.static(path.join(__dirname, 'public')));
app.use(express.static(path.join(__dirname, 'data', 'uploads')));
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
app.use(require('./routes/image-library'));
app.use(require('./routes/boards'));

app.get('/', (req, res) => res.redirect('/login.html'));

io.on('connection', (socket) => {
    console.log(`Socket连接: user ${socket.userId} (role ${socket.userRole})`);

    socket.on('join-board', ({ missionId, role }) => {
        const room = `mission-${missionId}-${role}`;
        socket.join(room);
        socket.currentBoardRoom = room;
        socket.currentMissionId = missionId;
    });

    socket.on('leave-board', () => {
        if (socket.currentBoardRoom) {
            socket.leave(socket.currentBoardRoom);
        }
    });

    socket.on('board:image-move', (data) => {
        if (socket.currentBoardRoom) {
            socket.to(socket.currentBoardRoom).emit('board:image-move', data);
        }
    });

    socket.on('board:image-resize', (data) => {
        if (socket.currentBoardRoom) {
            socket.to(socket.currentBoardRoom).emit('board:image-resize', data);
        }
    });

    socket.on('board:image-add', (data) => {
        if (socket.currentBoardRoom) {
            socket.to(socket.currentBoardRoom).emit('board:image-add', data);
            // Also notify player room so they see new images
            socket.to(`mission-${socket.currentMissionId}-ply`).emit('board:image-add', data);
        }
    });

    socket.on('board:image-remove', (data) => {
        if (socket.currentBoardRoom) {
            socket.to(socket.currentBoardRoom).emit('board:image-remove', data);
            socket.to(`mission-${socket.currentMissionId}-ply`).emit('board:image-remove', data);
        }
    });

    socket.on('board:image-rename', (data) => {
        if (socket.currentBoardRoom) {
            socket.to(socket.currentBoardRoom).emit('board:image-rename', data);
        }
    });

    socket.on('board:connection-add', (data) => {
        if (socket.currentBoardRoom) {
            socket.to(socket.currentBoardRoom).emit('board:connection-add', data);
            socket.to('mission-' + socket.currentMissionId + '-ply').emit('board:connection-add', data);
        }
    });

    socket.on('board:connection-remove', (data) => {
        if (socket.currentBoardRoom) {
            socket.to(socket.currentBoardRoom).emit('board:connection-remove', data);
            socket.to('mission-' + socket.currentMissionId + '-ply').emit('board:connection-remove', data);
        }
    });

    socket.on('disconnect', () => {
        console.log(`Socket断开: user ${socket.userId}`);
    });
});

server.listen(PORT, () => {
    console.log(`服务器运行中: http://localhost:${PORT}`);
    console.log(`数据目录: ${path.join(__dirname, 'data')}`);
});
