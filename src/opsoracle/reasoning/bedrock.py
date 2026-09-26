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
    """Evidence-grounded reasoning over an assembled investigation via Bedrock.

    The ``bedrock-runtime`` client is injectable (requirement 11.1): tests pass a
    stub/mock, while production leaves it ``None`` so a default client is built from the
    standard credential chain / IAM for the provided or environment region — credentials
    are never hard-coded (requirements 7.8, 9.1). If a default client cannot be built the
    reasoner degrades gracefully rather than raising, so the pipeline still produces a
    report (requirement 7.7).
    """

    def __init__(
        self,
        client: Any = None,
        *,
        model_id: str,
        max_tokens: int = 1500,
        enabled: bool = True,
        region: str | None = None,
    ) -> None:
        self._model_id = model_id
        self._max_tokens = max_tokens
        self._enabled = enabled
        self._region = region
        if client is not None:
            self._client = client
        elif enabled:
            # Build a default client from the credential chain only when reasoning is
            # actually enabled; a disabled reasoner never needs one.
            self._client = self._build_client(region)
        else:
            self._client = None
        # Exposed for measurability (requirement 10.3).
        self.last_usage: dict | None = None

    @staticmethod
    def _build_client(region: str | None) -> Any:
        """Build a default Boto3 ``bedrock-runtime`` client from the credential chain.

        Never accepts hard-coded credentials (requirements 7.8, 9.1); the region is the
        only optional hint. Any failure to construct a client (boto3 unavailable, no
        resolvable region, etc.) is logged and returns ``None`` so :meth:`reason`
        degrades to an "unavailable" result instead of raising (requirement 7.7).
        """
        try:
            import boto3
        except ImportError as exc:  # pragma: no cover - env-dependent
            logger.warning("boto3 unavailable; Bedrock reasoning disabled: %s", exc)
            return None
        try:
            kwargs: dict[str, Any] = {}
            if region:
                kwargs["region_name"] = region
            return boto3.client("bedrock-runtime", **kwargs)
        except Exception as exc:  # noqa: BLE001 - degrade gracefully on any failure
            logger.warning("could not create a Bedrock client: %s", exc)
            return None

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
