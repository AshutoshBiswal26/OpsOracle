"""Amazon Bedrock reasoning stage.

Invoked last, over already-assembled evidence, and only when it can add value
(requirement 7.1). Uses the Bedrock Converse API so the same code works across models.
Any failure degrades gracefully to ``ReasoningResult.unavailable(...)`` so the pipeline
still produces a report (requirement 7.7).
"""

from __future__ import annotations

import logging
from typing import Any

from ..errors import ReasoningError
from ..models.investigation import Investigation
from ..models.report import ReasoningResult
from . import prompt as prompt_mod
from .schema import parse_reasoning

logger = logging.getLogger("opsoracle.reasoning")


class BedrockReasoner:
    def __init__(
        self,
        client: Any,
        *,
        model_id: str,
        max_tokens: int = 1500,
        enabled: bool = True,
    ) -> None:
        self._client = client
        self._model_id = model_id
        self._max_tokens = max_tokens
        self._enabled = enabled
        # Exposed for measurability (requirement 10.3).
        self.last_usage: dict | None = None

    def reason(self, investigation: Investigation) -> ReasoningResult:
        if not self._enabled:
            return ReasoningResult.unavailable("reasoning disabled by configuration")
        if self._client is None:
            return ReasoningResult.unavailable("no Bedrock client configured")
        # Nothing to reason over -> skip the call entirely (requirement 7.1, cost).
        if not investigation.events:
            return ReasoningResult.unavailable("no evidence to reason over; skipped Bedrock")

        try:
            text = self._invoke(investigation)
            valid_ids = prompt_mod.valid_evidence_ids(investigation)
            return parse_reasoning(text, valid_ids)
        except ReasoningError as exc:
            logger.warning("reasoning failed: %s", exc)
            return ReasoningResult.unavailable(f"reasoning unavailable: {exc}")
        except Exception as exc:  # noqa: BLE001 - degrade gracefully on any failure
            logger.warning("bedrock invocation failed: %s", exc)
            return ReasoningResult.unavailable("reasoning unavailable: bedrock call failed")

    def _invoke(self, investigation: Investigation) -> str:
        user_prompt = prompt_mod.build_user_prompt(investigation)
        response = self._client.converse(
            modelId=self._model_id,
            system=[{"text": prompt_mod.SYSTEM_PROMPT}],
            messages=[{"role": "user", "content": [{"text": user_prompt}]}],
            inferenceConfig={"maxTokens": self._max_tokens, "temperature": 0.0},
        )
        self.last_usage = response.get("usage")
        if self.last_usage:
            logger.info(
                "bedrock usage input=%s output=%s total=%s",
                self.last_usage.get("inputTokens"),
                self.last_usage.get("outputTokens"),
                self.last_usage.get("totalTokens"),
            )
        return self._extract_text(response)

    @staticmethod
    def _extract_text(response: dict) -> str:
        try:
            content = response["output"]["message"]["content"]
        except (KeyError, TypeError) as exc:
            raise ReasoningError(f"unexpected Bedrock response shape: {exc}") from exc
        parts = [
            block["text"]
            for block in content
            if isinstance(block, dict) and "text" in block
        ]
        if not parts:
            raise ReasoningError("Bedrock response contained no text content")
        return "\n".join(parts)
