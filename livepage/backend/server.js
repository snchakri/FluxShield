// Import required packages
const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');

// Load environment variables
dotenv.config();

// Initialize Express app
const app = express();

// Middleware
app.use(express.json()); // Parse JSON request bodies
app.use(cors()); // Enable CORS for all routes

// Root route
app.get('/', (req, res) => {
  res.send('Backend Running');
});

// Import and use test router
const testRouter = require('./routes/test');
app.use('/api/test', testRouter);

// Import and use traffic router
const trafficRouter = require('./routes/traffic');
app.use('/api/traffic', trafficRouter);

// Import and use sync router
const syncRouter = require('./routes/sync');
app.use('/api/sync', syncRouter);

// Start the server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
