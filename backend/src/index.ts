import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import apiRoutes from './routes/index';

const app = express();
const PORT = parseInt(process.env.PORT ?? '3001', 10);

app.use(cors({
  origin: true,
  methods: ['GET', 'POST'],
}));

app.use(express.json({ limit: '4mb' }));

app.use('/api', apiRoutes);

app.get('/health', (_req, res) => {
  res.json({
    status: 'ok',
    service: 'Vultron v3',
    slither: 'enabled',
    groq: process.env.GROQ_API_KEY ? 'configured' : 'missing',
  });
});

app.listen(PORT, () => {
  console.log(`Vultron v3 backend running on http://localhost:${PORT}`);
  if (!process.env.GROQ_API_KEY) {
    console.warn('WARNING: GROQ_API_KEY is not set — AI features will fail');
  }
});
