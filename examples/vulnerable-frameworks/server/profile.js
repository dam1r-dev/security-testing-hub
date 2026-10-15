const _ = require('lodash');

app.post('/signup', async (req, res) => {
  const user = await User.create(req.body); // mass assignment
  res.json(user);
});

app.post('/settings', (req, res) => {
  _.merge(settings, req.body); // prototype pollution
  prefs[req.body.group][req.body.key] = req.body.value; // prototype pollution
  res.json(settings);
});
