const { listOllamaModels, generateOllamaFix, repairOllamaFix } = require('./ollama-provider');

const PROVIDERS = Object.freeze({ OLLAMA: 'ollama' });

function createAiProvider(provider, options = {}) {
  if (provider !== PROVIDERS.OLLAMA) throw new Error(`Fournisseur IA non pris en charge : ${provider}.`);
  const baseUrl = options.baseUrl || 'http://127.0.0.1:11434';
  const fetchImpl = options.fetchImpl;
  return Object.freeze({
    id: PROVIDERS.OLLAMA,
    locality: 'local',
    listModels: () => listOllamaModels(baseUrl, fetchImpl),
    generateFix: (request) => generateOllamaFix({ baseUrl, fetchImpl, ...request }),
    repairFix: (request) => repairOllamaFix({ baseUrl, fetchImpl, ...request })
  });
}

module.exports = { PROVIDERS, createAiProvider };
