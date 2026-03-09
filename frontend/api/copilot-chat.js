import { GoogleGenerativeAI } from '@google/generative-ai';

const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY ?? '');

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const { question, vulnerabilities = [], score = 100 } = req.body;
  if (!question?.trim()) return res.status(400).json({ error: 'Question required.' });

  const context = vulnerabilities.length > 0
    ? vulnerabilities.map(v => `- [${v.severity.toUpperCase()}] ${v.type} in ${v.function}(): ${v.description}`).join('\n')
    : `No vulnerabilities detected. Score: ${score}/100`;

  try {
    const model = genAI.getGenerativeModel({
      model: 'gemini-2.0-flash',
      generationConfig: { maxOutputTokens: 400 },
    });
    const result = await model.generateContent(
      `You are Vultron Copilot, a smart contract security assistant.
Security context:\n${context}\nScore: ${score}/100
Question: "${question}"
Answer concisely in 3-5 sentences. Plain text only.`
    );
    return res.status(200).json({ answer: result.response.text() });
  } catch (err) {
    return res.status(500).json({ error: 'Copilot failed.' });
  }
}
