// Minimal stand-in for the `axios` package, just so the analyzer sees an `axios.get()` call.
module.exports = {
  get(url) {
    return Promise.resolve({ data: null });
  },
};
