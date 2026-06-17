const zmq = require('zeromq');
const { pack, unpack } = require('msgpackr');

class WafBridge {
  constructor() {
    this.endpoint = process.env.WAF_ZMQ_ENDPOINT || 'tcp://ai-waf:5557';
    this.timeoutMs = Number(process.env.WAF_ZMQ_TIMEOUT_MS || 15);
    this.enabled = (process.env.WAF_ZMQ_ENABLED || 'true').toLowerCase() === 'true';
    this.sock = null;
    this.connected = false;
  }

  async connect() {
    if (!this.enabled || this.connected) {
      return;
    }

    this.sock = new zmq.Request({ linger: 0 });
    this.sock.connect(this.endpoint);
    this.connected = true;
  }

  async classify(payload, correlationId, sourceId = 'node-backend') {
    if (!this.enabled) {
      throw new Error('bridge disabled');
    }

    await this.connect();

    const reqBuffer = pack({
      payload,
      correlationId,
      sourceId,
    });

    const timeout = new Promise((_, reject) => {
      setTimeout(() => reject(new Error('bridge timeout')), this.timeoutMs);
    });

    const rpc = (async () => {
      await this.sock.send(reqBuffer);
      const [reply] = await this.sock.receive();
      const result = unpack(reply);
      if (!result || result.ok !== true) {
        const errorText = (result && result.error) || 'bridge classify failed';
        throw new Error(errorText);
      }
      return result;
    })();

    return Promise.race([rpc, timeout]);
  }

  close() {
    try {
      if (this.sock) {
        this.sock.close();
      }
    } catch (_error) {
      // no-op
    }
    this.connected = false;
    this.sock = null;
  }
}

module.exports = new WafBridge();
