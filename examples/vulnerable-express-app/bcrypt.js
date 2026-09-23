// Minimal stand-in for the `bcrypt` package.
module.exports = {
  compare(plain, hash) {
    return Promise.resolve(false);
  },
};
