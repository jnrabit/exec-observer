"""Fact extractor — backend-agnostisch (Ollama-Default oder injizierter Coder)."""

import json
import logging
import re
from typing import Optional, Protocol

import requests

from ossifikat.store import OssifikatStore

logger = logging.getLogger(__name__)


class Generator(Protocol):
    """Minimal-Vertrag für ein injizierbares Sprachmodell-Backend.

    Erfüllt von vibelikes QwenCoder/ClaudeCoder (gemeinsame generate-Signatur).
    Die Abhängigkeit zeigt von vibelike -> ossifikat: ossifikat importiert die
    konkreten Coder NICHT, sondern bekommt ein generate-fähiges Objekt gereicht.
    """

    def generate(
        self, prompt: str, system: str = None, temperature: float = 0.2,
        stream: bool = False,
    ) -> str: ...


class QwenExtractor:
    """Extract triples from text.

    Zwei Modi:
      * Default (backend=None): direkter Ollama-Call (rückwärtskompatibel).
      * Injiziert (backend=<Generator>): nutzt die gemeinsame Modell-Naht
        (Claude jetzt, schwach-lokal später — dieselbe Env-Var im Aufrufer).

    Das staging->confirm->ossify-Gate bleibt die Determinismus-Schiene: ein
    schwaches Backend kann den Store nicht vergiften, schlechte Tripel hängen
    in Staging bis zur menschlichen Bestätigung.
    """

    SYSTEM_PROMPT = """Du bist ein Fakten-Extraktor. Zerlege den gegebenen Text in atomare Fakten als Subject-Predicate-Object Triples.

Regeln:
- Nur explizit im Text genannte Fakten, keine Schlussfolgerungen.
- Predicate immer kurz, am besten ein Verb oder eine Relation (z.B. "ist", "hat", "wurde_geboren_in").
- Confidence: 1.0 wenn der Fakt klar im Text steht, niedriger wenn unsicher.
- Antworte AUSSCHLIESSLICH mit gültigem JSON-Array, kein Fließtext drumherum.
- Wenn keine Fakten extrahierbar: leeres Array [].

Antwort-Format:
[
  {"subject": "...", "predicate": "...", "object": "...", "confidence": 0.9},
  ...
]"""

    def __init__(
        self, model: str = "qwen2.5-coder:7b", ollama_url: str = "http://localhost:11434",
        backend: Optional[Generator] = None,
    ) -> None:
        """Initialize extractor.

        backend: optionales generate-fähiges Objekt. Wenn gesetzt, ersetzt es den
                 direkten Ollama-Call (model/ollama_url werden dann ignoriert).
        """
        self.model = model
        self.ollama_url = ollama_url.rstrip("/")
        self.api_endpoint = f"{self.ollama_url}/api/generate"
        self.backend = backend

    def _generate(self, text: str) -> str:
        """Hole die rohe Modell-Antwort — via injiziertes Backend oder Ollama."""
        prompt = f"Extrahiere alle Triples aus diesem Text:\n\n{text}"
        if self.backend is not None:
            return self.backend.generate(
                prompt, system=self.SYSTEM_PROMPT, temperature=0.2, stream=False
            ) or ""
        response = requests.post(
            self.api_endpoint,
            json={
                "model": self.model,
                "system": self.SYSTEM_PROMPT,
                "prompt": prompt,
                "stream": False,
            },
            timeout=60,
        )
        response.raise_for_status()
        return (response.json().get("response") or "").strip()

    def extract(self, text: str) -> list[dict]:
        """Extract triples from text. Returns list of {subject, predicate, object, confidence}."""
        if not text or not text.strip():
            return []

        try:
            response_text = self._generate(text)
            if not response_text:
                return []
            return self._parse_json_response(response_text)

        except requests.RequestException as e:
            logger.exception(f"Ollama request failed: {e}")
            return []
        except Exception as e:
            logger.exception(f"Unexpected error in extract: {e}")
            return []

    def _parse_json_response(self, text: str) -> list[dict]:
        """Parse JSON response with fallback to regex extraction."""
        # Reasoning-Backends (qwen3) klammern Denkschritte in <think>…</think> —
        # vor dem JSON-Scan entfernen, sonst frisst der greedy-Regex deren Klammern.
        text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            logger.debug(f"JSON parse failed, trying regex fallback")
            match = re.search(r"\[.*\]", text, re.DOTALL)
            if match:
                try:
                    return json.loads(match.group(0))
                except json.JSONDecodeError:
                    logger.warning(f"Regex fallback also failed for response: {text[:100]}")
                    return []
            logger.warning(f"No JSON array found in response: {text[:100]}")
            return []

    def extract_and_stage(
        self, text: str, store: OssifikatStore, source: str = "qwen-extractor"
    ) -> list[int]:
        """Extract triples and add to staging. Returns list of triple IDs."""
        triples = self.extract(text)
        ids = []

        for triple in triples:
            try:
                triple_id = store.add_staging(
                    subject=triple.get("subject", ""),
                    predicate=triple.get("predicate", ""),
                    object=triple.get("object", ""),
                    source=source,
                    confidence=float(triple.get("confidence", 1.0)),
                )
                ids.append(triple_id)
            except (KeyError, ValueError, TypeError) as e:
                logger.warning(f"Failed to stage triple {triple}: {e}")

        return ids
