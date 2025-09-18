const express = require('express');
const app = express();
const profileRoutes = require('./routes/profile');

app.use(express.json());
app.use('/api/profile', profileRoutes);

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});