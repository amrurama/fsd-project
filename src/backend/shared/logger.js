const log = (service, message, meta = {}) => {
  const payload = {
    service,
    message,
    ...meta,
    timestamp: new Date().toISOString()
  };
  console.log(JSON.stringify(payload));
};

module.exports = { log };
