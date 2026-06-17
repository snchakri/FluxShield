// Import Express
const express = require('express');

// Create router
const router = express.Router();

// GET route: /api/test/
router.get('/', (req, res) => {
  res.json({ message: 'API Works' });
});

// Export router
module.exports = router;
