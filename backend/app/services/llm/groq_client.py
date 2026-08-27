"""Thin wrapper around the Groq SDK for structured (schema-validated)
completions.

Every LLM call in this pipeline goes through `structured_completion` --
nothing else in this codebase calls `groq.Groq()` directly, so retry
behaviour, error translation, and the strict-schema conversion all live
in exactly one place.
"""

import json
import logging
import time
from typing import TypeVar

from groq import APIStatusError, Groq
from pydantic import BaseModel

from app.config import settings

logger = logging.getLogger("netsentinel.llm")

ModelT = TypeVar("ModelT", bound=BaseModel)

_MAX_RETRIES = 2
_RETRY_DELAY_SECONDS = 2.0


class LLMUnavailableError(RuntimeError):
    """Raised when Groq can't be reached, is rate-limited past retry, or
    won't return a schema-valid response -- routers turn this into a
    clean failure response instead of a 500 stack trace.
    """


def _client() -> Groq:
    if not settings.llm_api_key:
        raise LLMUnavailableError(
            "LLM_API_KEY is not set in backend/.env -- sign up free (no card) at "
            "https://console.groq.com and add your key before running an investigation."
        )
    return Groq(api_key=settings.llm_api_key)


def _strict_schema(model: type[BaseModel]) -> dict:
    """Groq's strict json_schema mode requires every property listed under
    `required` and `additionalProperties: false` at every object level,
    including nested ones (e.g. `Citation` inside a list) -- Pydantic
    doesn't emit that shape by default for fields that have Python-side
    defaults (like `citations: list[Citation] = []`), so it's rebuilt
    here rather than hand-duplicating each schema.
    """
    schema = model.model_json_schema()
    defs = schema.pop("$defs", {})

    def strictify(node: dict) -> None:
        if node.get("type") == "object" and "properties" in node:
            node["required"] = list(node["properties"].keys())
            node["additionalProperties"] = False
            for prop_schema in node["properties"].values():
                strictify(prop_schema)
        if node.get("type") == "array" and "items" in node:
            strictify(node["items"])

    for definition in defs.values():
        strictify(definition)
    strictify(schema)

    if defs:
        schema["$defs"] = defs
    return schema


def structured_completion(
    model: str,
    system_prompt: str,
    user_prompt: str,
    schema: type[ModelT],
) -> ModelT:
    """One schema-validated Groq call.

    Retries a bounded number of times on rate limiting; raises
    LLMUnavailableError (never a raw SDK/JSON exception) if it never
    succeeds. A response that fails schema validation is treated as a
    failure, not silently coerced -- callers can rely on getting back
    either a valid `schema` instance or this one exception type.
    """
    client = _client()
    json_schema = _strict_schema(schema)

    last_error: Exception | None = None
    for attempt in range(_MAX_RETRIES + 1):
        try:
            response = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                response_format={
                    "type": "json_schema",
                    "json_schema": {
                        "name": schema.__name__,
                        "strict": True,
                        "schema": json_schema,
                    },
                },
            )
            content = response.choices[0].message.content or "{}"
            return schema.model_validate(json.loads(content))
        except APIStatusError as exc:
            last_error = exc
            body_code = (exc.body or {}).get("error", {}).get("code") if isinstance(exc.body, dict) else None
            # 429 is a real rate limit. 400/json_validate_failed is a
            # different, genuinely transient failure: the model occasionally
            # emits malformed JSON even under strict mode (observed in
            # testing -- e.g. a spelled-out digit mid-number breaking the
            # parser). Both are worth a fresh attempt; a schema/model-name
            # problem would just fail identically every retry, so nothing
            # else here is retried.
            if (exc.status_code == 429 or body_code == "json_validate_failed") and attempt < _MAX_RETRIES:
                logger.warning(
                    "Groq call to %s failed (%s), retrying in %.0fs",
                    model,
                    body_code or exc.status_code,
                    _RETRY_DELAY_SECONDS,
                )
                time.sleep(_RETRY_DELAY_SECONDS)
                continue
            break
        except Exception as exc:  # schema validation / malformed JSON / network error
            last_error = exc
            break

    raise LLMUnavailableError(f"Groq call to {model} failed: {last_error}") from last_error
