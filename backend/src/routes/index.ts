import { Router } from 'express';
import { handleAnalyze, handleCopilotChat } from '../controllers/analyzeController';

const router = Router();

router.post('/analyze', handleAnalyze);
router.post('/copilot-chat', handleCopilotChat);

export default router;
