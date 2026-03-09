import { Router } from 'express';
import { analyzeContractHandler } from '../controllers/analyzeController';

const router = Router();

router.post('/analyze', analyzeContractHandler);

export default router;
