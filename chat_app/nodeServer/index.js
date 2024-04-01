// Importing required modules
const http = require('http');
const socketIO = require('socket.io');

// Create a server
const server = http.createServer((req, res) => {
    // Handle HTTP requests if needed
});

// Initialize Socket.IO server with CORS enabled
const io = socketIO(server, {
  cors: {
    origin: '*',
    methods: ['GET', 'POST']
  }
});

// Object to store users
const users = {};

// Handle socket connections
io.on('connection', socket => {
    // If any new user joins, let other users connected to the server know!
    socket.on('new-user-joined', name => {
        users[socket.id] = { name: name }; // Store user information using socket.id as the key
        socket.broadcast.emit('user-joined', name); // Announces user joined 
    });

    // If someone sends a message, broadcast it to other people
    socket.on('send', message => {
        socket.broadcast.emit('receive', { message: message, name: users[socket.id].name }); // Retrieve user name using socket.id
    });

    // If someone leaves the chat, let others know 
    socket.on('disconnect', () => {
        socket.broadcast.emit('left', users[socket.id].name); // Retrieve user name using socket.id
        delete users[socket.id];
    });
});

// Start the server
const PORT = process.env.PORT || 8000;
server.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
