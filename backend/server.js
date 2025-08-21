const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
require('dotenv').config();

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

// Middleware
app.use(cors());
app.use(express.json());

// Serve frontend in production
if (process.env.NODE_ENV === 'production') {
  app.use(express.static(path.join(__dirname, '../frontend')));
  
  app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, '../frontend', 'index.html'));
  });
}

// MongoDB Connection
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://ellyongiro8:QwXDXE6tyrGpUTNb@cluster0.tyxcmm9.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0';
mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log('Connected to MongoDB'))
.catch(err => console.error('MongoDB connection error:', err));

// User Schema
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  friends: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  friendRequests: [{
    from: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    status: { type: String, enum: ['pending', 'accepted', 'rejected'], default: 'pending' }
  }],
  online: { type: Boolean, default: false },
  lastSeen: { type: Date, default: Date.now }
});

// Message Schema
const messageSchema = new mongoose.Schema({
  sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  receiver: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  content: { type: String, required: true },
  timestamp: { type: Date, default: Date.now },
  read: { type: Boolean, default: false }
});

// Models
const User = mongoose.model('User', userSchema);
const Message = mongoose.model('Message', messageSchema);

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'bera_secret_key';

// Authentication Middleware
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.userId).select('-password');
    if (!user) {
      return res.status(403).json({ error: 'Invalid token' });
    }
    req.user = user;
    next();
  } catch (error) {
    return res.status(403).json({ error: 'Invalid or expired token' });
  }
};

// Routes

// Register
app.post('/api/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;

    // Check if user exists
    const existingUser = await User.findOne({ 
      $or: [{ email }, { username }] 
    });
    
    if (existingUser) {
      return res.status(400).json({ 
        error: 'User with this email or username already exists' 
      });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user
    const user = new User({
      username,
      email,
      password: hashedPassword
    });

    await user.save();

    // Generate token
    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '24h' });

    res.status(201).json({
      message: 'User created successfully',
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email
      }
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Find user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    // Check password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    // Update online status
    user.online = true;
    await user.save();

    // Generate token
    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '24h' });

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get user profile
app.get('/api/user/:id', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.params.id).select('-password');
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json(user);
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Search users
app.get('/api/users/search', authenticateToken, async (req, res) => {
  try {
    const { q } = req.query;
    const users = await User.find({
      username: { $regex: q, $options: 'i' },
      _id: { $ne: req.user._id }
    }).select('username online lastSeen');
    
    res.json(users);
  } catch (error) {
    console.error('Search users error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Send friend request
app.post('/api/friend-request/:userId', authenticateToken, async (req, res) => {
  try {
    const receiverId = req.params.userId;
    
    // Check if users are the same
    if (req.user._id.toString() === receiverId) {
      return res.status(400).json({ error: 'Cannot send friend request to yourself' });
    }

    // Check if receiver exists
    const receiver = await User.findById(receiverId);
    if (!receiver) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Check if already friends
    if (req.user.friends.includes(receiverId)) {
      return res.status(400).json({ error: 'Already friends with this user' });
    }

    // Check if request already exists
    const existingRequest = receiver.friendRequests.find(
      request => request.from.toString() === req.user._id.toString()
    );

    if (existingRequest) {
      return res.status(400).json({ error: 'Friend request already sent' });
    }

    // Add friend request
    receiver.friendRequests.push({
      from: req.user._id,
      status: 'pending'
    });

    await receiver.save();

    // Notify receiver via socket if online
    const receiverSocket = onlineUsers[receiverId];
    if (receiverSocket) {
      io.to(receiverSocket).emit('friendRequest', {
        from: {
          id: req.user._id,
          username: req.user.username
        }
      });
    }

    res.json({ message: 'Friend request sent successfully' });
  } catch (error) {
    console.error('Send friend request error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Respond to friend request
app.post('/api/friend-request/:requestId/respond', authenticateToken, async (req, res) => {
  try {
    const { status } = req.body; // 'accepted' or 'rejected'
    const requestId = req.params.requestId;

    const user = await User.findById(req.user._id);
    
    // Find the friend request
    const request = user.friendRequests.id(requestId);
    if (!request) {
      return res.status(404).json({ error: 'Friend request not found' });
    }

    if (request.status !== 'pending') {
      return res.status(400).json({ error: 'Friend request already processed' });
    }

    // Update request status
    request.status = status;

    // If accepted, add to friends list for both users
    if (status === 'accepted') {
      user.friends.push(request.from);
      
      const requester = await User.findById(request.from);
      requester.friends.push(user._id);
      await requester.save();

      // Notify requester via socket if online
      const requesterSocket = onlineUsers[requester._id.toString()];
      if (requesterSocket) {
        io.to(requesterSocket).emit('friendRequestAccepted', {
          by: {
            id: user._id,
            username: user.username
          }
        });
      }
    }

    await user.save();

    res.json({ message: `Friend request ${status}` });
  } catch (error) {
    console.error('Respond to friend request error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get friends list
app.get('/api/friends', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user._id)
      .populate('friends', 'username online lastSeen');
    
    res.json(user.friends);
  } catch (error) {
    console.error('Get friends error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get messages between users
app.get('/api/messages/:friendId', authenticateToken, async (req, res) => {
  try {
    const friendId = req.params.friendId;
    
    // Verify friendship
    const user = await User.findById(req.user._id);
    if (!user.friends.includes(friendId)) {
      return res.status(403).json({ error: 'You can only message friends' });
    }

    const messages = await Message.find({
      $or: [
        { sender: req.user._id, receiver: friendId },
        { sender: friendId, receiver: req.user._id }
      ]
    })
    .populate('sender', 'username')
    .populate('receiver', 'username')
    .sort({ timestamp: 1 });

    res.json(messages);
  } catch (error) {
    console.error('Get messages error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Socket.IO for real-time messaging
const onlineUsers = {};

io.on('connection', (socket) => {
  console.log('User connected:', socket.id);

  // User authentication for socket
  socket.on('authenticate', async (token) => {
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      const user = await User.findById(decoded.userId);
      
      if (user) {
        // Store socket ID for this user
        onlineUsers[user._id.toString()] = socket.id;
        socket.userId = user._id.toString();
        
        // Update user online status
        user.online = true;
        await user.save();
        
        // Notify friends
        user.friends.forEach(friendId => {
          const friendSocket = onlineUsers[friendId.toString()];
          if (friendSocket) {
            io.to(friendSocket).emit('userOnline', { userId: user._id.toString() });
          }
        });
        
        console.log(`User ${user.username} authenticated on socket`);
      }
    } catch (error) {
      console.error('Socket authentication error:', error);
    }
  });

  // Handle sending messages
  socket.on('sendMessage', async (data) => {
    try {
      const { receiverId, content } = data;
      
      // Verify friendship
      const sender = await User.findById(socket.userId);
      if (!sender.friends.includes(receiverId)) {
        socket.emit('error', { message: 'You can only message friends' });
        return;
      }

      // Create and save message
      const message = new Message({
        sender: socket.userId,
        receiver: receiverId,
        content
      });

      await message.save();

      // Populate message with sender info
      await message.populate('sender', 'username');
      
      // Send to receiver if online
      const receiverSocket = onlineUsers[receiverId];
      if (receiverSocket) {
        io.to(receiverSocket).emit('newMessage', message);
      }

      // Send back to sender for confirmation
      socket.emit('messageSent', message);
    } catch (error) {
      console.error('Send message error:', error);
      socket.emit('error', { message: 'Failed to send message' });
    }
  });

  // Handle typing indicators
  socket.on('typing', async (data) => {
    try {
      const { receiverId, isTyping } = data;
      
      // Verify friendship
      const sender = await User.findById(socket.userId);
      if (!sender.friends.includes(receiverId)) {
        return;
      }

      // Send typing indicator to receiver
      const receiverSocket = onlineUsers[receiverId];
      if (receiverSocket) {
        io.to(receiverSocket).emit('typing', {
          userId: socket.userId,
          isTyping
        });
      }
    } catch (error) {
      console.error('Typing indicator error:', error);
    }
  });

  // Handle disconnect
  socket.on('disconnect', async () => {
    try {
      if (socket.userId) {
        // Remove from online users
        delete onlineUsers[socket.userId];
        
        // Update user online status
        const user = await User.findById(socket.userId);
        if (user) {
          user.online = false;
          user.lastSeen = new Date();
          await user.save();
          
          // Notify friends
          user.friends.forEach(friendId => {
            const friendSocket = onlineUsers[friendId.toString()];
            if (friendSocket) {
              io.to(friendSocket).emit('userOffline', { userId: user._id.toString() });
            }
          });
        }
      }
      
      console.log('User disconnected:', socket.id);
    } catch (error) {
      console.error('Disconnect error:', error);
    }
  });
});

// Start server
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Bera server running on port ${PORT}`);
});
