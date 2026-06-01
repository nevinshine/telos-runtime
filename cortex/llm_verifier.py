"""
Telos Cognitive Intent Verifier (Phase 4)

Uses TinyLlama-1.1B with logprobs-based classification.
Instead of trusting greedy text output, we compare the model's
token-level confidence in RELEVANT vs IRRELEVANT.

This is the architecturally correct approach for small LLMs:
they may not generate the right token, but their internal
probabilities often reflect the correct answer.
"""

import logging
import math
import os
import time
from functools import lru_cache
from typing import Optional, Tuple

log = logging.getLogger("telos.llm")

MODELS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "models"
)

MODEL_CANDIDATES = [
    os.environ.get("TELOS_LLM_MODEL", ""),
    os.path.join(MODELS_DIR, "tinyllama.gguf"),
    os.path.join(MODELS_DIR, "tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf"),
]

# Confidence threshold: if P(IRRELEVANT)/P(RELEVANT) > this ratio, deny.
# Lower = more strict. 0.25 means IR only needs 25% as much probability as RE to trigger deny.
DENY_THRESHOLD = 0.25

FEW_SHOT_PROMPT = """Classify if a network domain is relevant to a user goal. Answer RELEVANT or IRRELEVANT.

Goal: "check the weather forecast"
Domain: "weather.gov"
Answer: RELEVANT

Goal: "check the weather forecast"
Domain: "evil-malware.com"
Answer: IRRELEVANT

Goal: "read news articles"
Domain: "bbc.com"
Answer: RELEVANT

Goal: "read news articles"  
Domain: "attacker.com"
Answer: IRRELEVANT

Goal: "search for python libraries"
Domain: "pypi.org"
Answer: RELEVANT

Goal: "search for python libraries"
Domain: "facebook.com"
Answer: IRRELEVANT

Goal: "{goal}"
Domain: "{domain}"
Answer:"""


def _find_model():
    for path in MODEL_CANDIDATES:
        if path and os.path.isfile(path):
            return path
    return None


class LLMVerifier:
    def __init__(self, model_path=None, n_ctx=512, n_threads=4):
        self.model = None
        self.model_path = model_path or _find_model()
        self.n_ctx = n_ctx
        self.n_threads = n_threads
        self._load_model()

    def _load_model(self):
        try:
            from llama_cpp import Llama
            if not self.model_path or not os.path.exists(self.model_path):
                log.warning("LLM model not found. Searched: %s", MODELS_DIR)
                log.warning("Download: ./scripts/download_model.sh")
                return
            log.info("Loading Cognitive Engine: %s", os.path.basename(self.model_path))
            t0 = time.time()
            self.model = Llama(
                model_path=self.model_path,
                n_ctx=self.n_ctx,
                n_threads=self.n_threads,
                n_gpu_layers=0,
                verbose=False,
                logits_all=True
            )
            elapsed = time.time() - t0
            log.info("Cognitive Engine Online (%.1fs)", elapsed)
        except ImportError:
            log.warning("llama-cpp-python not installed -> Heuristic Mode")
        except Exception as e:
            log.error("Failed to load LLM: %s", e)

    @property
    def is_available(self):
        return self.model is not None or "OPENAI_API_KEY" in os.environ

    @lru_cache(maxsize=1024)
    def _cached_verify(self, goal, domain):
        return self._infer(goal, domain)

    def verify_action(self, goal, domain):
        if not self.is_available:
            return None
        try:
            return self._cached_verify(goal.lower().strip(), domain.lower().strip())
        except Exception as e:
            log.error("LLM inference failed: %s", e)
            return None

    def _infer(self, goal, domain):
        prompt = FEW_SHOT_PROMPT.format(goal=goal, domain=domain)
        start_time = time.time()

        if self.model is None and "OPENAI_API_KEY" in os.environ:
            import requests
            headers = {
                "Authorization": f"Bearer {os.environ['OPENAI_API_KEY']}",
                "Content-Type": "application/json"
            }
            data = {
                "model": "gpt-4o-mini",
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": 5,
                "temperature": 0.0
            }
            try:
                r = requests.post("https://api.openai.com/v1/chat/completions", headers=headers, json=data, timeout=10)
                r.raise_for_status()
                result = r.json()
                text = result["choices"][0]["message"]["content"].strip().upper()
                latency = time.time() - start_time
                is_allowed = "RELEVANT" in text
                verdict = "ALLOW" if is_allowed else "DENY"
                log.info("[LLM-OpenAI] %s -> %s: %s [%.0fms]", goal, domain, verdict, latency * 1000)
                return is_allowed, f"Cognitive(OpenAI): domain is {'relevant' if is_allowed else 'NOT relevant'} to goal"
            except Exception as e:
                log.error("OpenAI API failed: %s", e)
                return False, "Cognitive(OpenAI): API failure (fail-closed)"

        response = self.model(
            prompt,
            max_tokens=3,
            temperature=0.0,
            logprobs=5
        )
        latency = time.time() - start_time

        # Extract logprobs for first token
        logprobs_data = response["choices"][0].get("logprobs", {})
        top_logprobs = logprobs_data.get("top_logprobs", [{}])
        
        if not top_logprobs:
            log.warning("No logprobs available, defaulting to DENY")
            return False, "Cognitive: no confidence data (fail-closed)"

        first_token_probs = top_logprobs[0]
        
        # Get probabilities for RELEVANT and IRRELEVANT tokens
        p_relevant = math.exp(float(first_token_probs.get(" RE", first_token_probs.get("RE", -100))))
        p_irrelevant = math.exp(float(first_token_probs.get(" IR", first_token_probs.get("IR", -100))))
        
        # Confidence ratio
        ratio = p_irrelevant / max(p_relevant, 1e-10)
        
        raw_text = response["choices"][0]["text"].strip()
        is_allowed = ratio < DENY_THRESHOLD
        
        verdict = "ALLOW" if is_allowed else "DENY"
        log.info("[LLM] %s -> %s: %s (P_rel=%.3f P_irr=%.3f ratio=%.3f) [%.0fms]",
                 goal, domain, verdict, p_relevant, p_irrelevant, ratio, latency * 1000)

        reason = "Cognitive: domain is relevant (confidence: {:.0f}%)".format(p_relevant * 100) if is_allowed else "Cognitive: domain NOT relevant to goal (confidence: {:.0f}%)".format(p_irrelevant * 100)
        return is_allowed, reason
