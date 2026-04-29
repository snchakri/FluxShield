const express = require('express');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(express.json({ limit: '1mb' }));

const PORT = process.env.PORT || 7000;
const STORAGE_DIR = process.env.FILE_DB_PATH || '/data';
fs.mkdirSync(STORAGE_DIR, { recursive: true });

function resolveChannelPath(channelName) {
  if (!/^[a-zA-Z0-9_-]+$/.test(channelName)) {
    return null;
  }
  return path.join(STORAGE_DIR, `${channelName}.jsonl`);
}

app.get('/health', (_request, response) => {
  response.json({ status: 'ok', storageDir: STORAGE_DIR });
});

app.post('/append', (request, response) => {
  const { channel, record } = request.body || {};

  if (!channel || typeof channel !== 'string' || typeof record === 'undefined') {
    return response.status(400).json({ error: 'channel and record are required' });
  }

  const filePath = resolveChannelPath(channel);
  if (!filePath) {
    return response.status(400).json({ error: 'invalid channel name' });
  }

  const envelope = {
    writtenAt: new Date().toISOString(),
    record,
  };

  fs.appendFileSync(filePath, `${JSON.stringify(envelope)}\n`, 'utf-8');
  return response.json({ status: 'written' });
});

app.get('/records', (request, response) => {
  const channel = request.query.channel;
  const limitRaw = request.query.limit;
  const limit = Math.max(1, Math.min(Number(limitRaw || 100), 500));

  if (!channel || typeof channel !== 'string') {
    return response.status(400).json({ error: 'channel query param is required' });
  }

  const filePath = resolveChannelPath(channel);
  if (!filePath) {
    return response.status(400).json({ error: 'invalid channel name' });
  }

  if (!fs.existsSync(filePath)) {
    return response.json({ records: [] });
  }

  const raw = fs.readFileSync(filePath, 'utf-8');
  const lines = raw.split('\n').filter(Boolean);
  const selected = lines.slice(-limit).reverse().map((line) => JSON.parse(line));

  return response.json({ records: selected });
});

app.listen(PORT, () => {
  console.log(`file-db service running on http://0.0.0.0:${PORT}`);
});
