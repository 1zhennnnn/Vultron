import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import apiRoutes from './routes/index';

const app = express();
const PORT = parseInt(process.env.PORT ?? '5000', 10);

const allowedOrigins = [
  'http://localhost:5173',
  'http://localhost:3000',
  process.env.FRONTEND_URL,
].filter(Boolean) as string[];

app.use(cors({
  origin: (origin, cb) => {
    // Allow requests with no origin (curl, Postman, server-to-server)
    if (!origin) return cb(null, true);
    if (allowedOrigins.some(o => origin.startsWith(o)) || origin.endsWith('.vercel.app') || origin.endsWith('.netlify.app')) {
      return cb(null, true);
    }
    cb(new Error(`CORS: origin ${origin} not allowed`));
  },
  methods: ['GET', 'POST'],
}));

app.use(express.json({ limit: '4mb' }));

app.use('/api', apiRoutes);

app.get('/api/health', (_req, res) => {
  res.json({
    status: 'ok',
    service: 'Vultron v3',
    groq: process.env.GROQ_API_KEY ? 'configured' : 'missing',
  });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Vultron v3 backend running on port ${PORT}`);
  if (!process.env.GROQ_API_KEY) {
    console.warn('WARNING: GROQ_API_KEY is not set — AI features will fail');
  }
});
