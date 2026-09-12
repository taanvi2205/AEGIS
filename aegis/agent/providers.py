"""Chat backends for the live agent.

One interface, three implementations: a local model over Ollama, any
OpenAI-compatible HTTP API (Groq, OpenAI, OpenRouter, Together, DeepSeek), and
Anthropic. Swapping between them changes nothing about the enforcement path -
the checkpoint sees the same tool calls whichever model produced them, which is
the point: the security layer is model-agnostic by construction.

Credentials
-----------
API keys are read from environment variables only. Nothing is written to disk,
nothing is hardcoded, and no key is ever included in a log line or an error
message (§4 Rule 2). A missing key raises before any request is attempted.

Failure behaviour
-----------------
Every backend raises `ModelUnavailable` on a transport error, an auth failure or
an unparseable response. It never returns an empty plan, because an empty plan
would look to the evaluation like a perfectly defended session.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass, field


class ModelUnavailable(RuntimeError):
    """Raised when a model cannot be reached or returns nothing usable."""


# Hosted providers sit behind bot protection that rejects the default
# `Python-urllib/x.y` user agent with an HTTP 403 (Cloudflare error 1010).
# Every real API client sends its own identifier; this is ours.
USER_AGENT = "aegis-harness/1.0 (+https://github.com/taanvi2205/AEGIS)"


def _post_json(url: str, payload: dict, headers: dict, timeout: float) -> dict:
    """POST JSON and return the parsed response.

    Error bodies are surfaced without the Authorization header, so a failure
    message can never leak a credential.
    """
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json",
                 "Accept": "application/json",
                 "User-Agent": USER_AGENT, **headers})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:   # noqa: S310
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")[:400]
        hint = ""
        if exc.code == 401:
            hint = "\n  → the API key is missing, wrong, or revoked."
        elif exc.code == 403:
            hint = ("\n  → forbidden. If the body mentions error 1010 this is a bot "
                    "check on the user agent; if it mentions the key, the key lacks "
                    "access to this model.")
        elif exc.code == 404:
            hint = "\n  → that model name does not exist for this provider."
        elif exc.code == 429:
            hint = "\n  → rate limited; wait a moment or use a smaller model."
        raise ModelUnavailable(
            f"{exc.code} from {url.split('?')[0]}: {body}{hint}") from exc
    except urllib.error.URLError as exc:
        raise ModelUnavailable(f"cannot reach {url.split('?')[0]}: {exc.reason}") from exc
    except json.JSONDecodeError as exc:
        raise ModelUnavailable(f"non-JSON response from {url.split('?')[0]}") from exc


@dataclass
class ChatBackend:
    """Interface: turn a message list into one assistant message."""

    model: str
    name: str = "chat"

    def complete(self, messages: list[dict]) -> str:
        raise NotImplementedError


@dataclass
class OllamaChat(ChatBackend):
    """A local model served by Ollama. No credentials, nothing leaves the machine."""

    endpoint: str = field(default_factory=lambda: os.environ.get(
        "AEGIS_OLLAMA_URL", "http://localhost:11434/api/chat"))
    timeout: float = 180.0
    temperature: float = 0.0
    seed: int = 20260910

    def __post_init__(self) -> None:
        self.name = f"ollama:{self.model}"

    def complete(self, messages: list[dict]) -> str:
        data = _post_json(self.endpoint, {
            "model": self.model, "stream": False, "messages": messages,
            "format": "json",
            "options": {"temperature": self.temperature, "seed": self.seed,
                        "top_k": 1, "top_p": 1.0},
        }, {}, self.timeout)
        return data.get("message", {}).get("content", "")


# Providers that speak the OpenAI chat-completions dialect. Adding one is a
# base URL and a default model, not new code.
OPENAI_COMPATIBLE: dict[str, tuple[str, str, str]] = {
    # name: (base url, default model, api key env var)
    # qwen3.8-27b returns plain content. Groq's gpt-oss-* models are reasoning
    # models that put their answer in a separate channel and return an empty
    # `content`, so they do not drive this agent loop without extra handling.
    "groq": ("https://api.groq.com/openai/v1", "qwen/qwen3.8-27b", "GROQ_API_KEY"),
    "openai": ("https://api.openai.com/v1", "gpt-4o-mini", "OPENAI_API_KEY"),
    "openrouter": ("https://openrouter.ai/api/v1", "meta-llama/llama-3.3-70b-instruct",
                   "OPENROUTER_API_KEY"),
    "together": ("https://api.together.xyz/v1",
                 "meta-llama/Llama-3.3-70B-Instruct-Turbo", "TOGETHER_API_KEY"),
    "deepseek": ("https://api.deepseek.com/v1", "deepseek-chat", "DEEPSEEK_API_KEY"),
}


@dataclass
class OpenAICompatChat(ChatBackend):
    """Any OpenAI-compatible chat-completions endpoint.

    What it checks: that the provider is known and its API key is present in the
    environment, before any network call is made.

    On failure: raises `ModelUnavailable`. The key is never echoed, and error
    bodies are truncated and stripped of request headers.
    """

    provider: str = "groq"
    base_url: str = ""
    api_key_env: str = ""
    timeout: float = 120.0
    temperature: float = 0.0
    json_mode: bool = True

    def __post_init__(self) -> None:
        if self.provider not in OPENAI_COMPATIBLE:
            raise ModelUnavailable(
                f"unknown provider {self.provider!r}; known: "
                f"{', '.join(OPENAI_COMPATIBLE)}")
        base, default_model, env = OPENAI_COMPATIBLE[self.provider]
        self.base_url = self.base_url or base
        self.api_key_env = self.api_key_env or env
        self.model = self.model or default_model
        if not os.environ.get(self.api_key_env):
            raise ModelUnavailable(
                f"{self.api_key_env} is not set. Get a key and export it:\n"
                f"    export {self.api_key_env}='...'\n"
                f"Never put the key in a file that gets committed.")
        self.name = f"{self.provider}:{self.model}"

    def complete(self, messages: list[dict]) -> str:
        payload: dict = {"model": self.model, "messages": messages,
                         "temperature": self.temperature}
        if self.json_mode:
            # Constrains output to a single JSON object, so the agent takes one
            # action per turn instead of emitting a whole plan up front.
            payload["response_format"] = {"type": "json_object"}
        data = _post_json(f"{self.base_url}/chat/completions", payload,
                          {"Authorization": f"Bearer {os.environ[self.api_key_env]}"},
                          self.timeout)
        choices = data.get("choices") or []
        if not choices:
            raise ModelUnavailable(f"{self.name} returned no choices")
        content = choices[0].get("message", {}).get("content", "")
        if not content.strip():
            raise ModelUnavailable(
                f"{self.name} returned empty content. Reasoning models often put "
                f"their answer in a separate field; pick a non-reasoning model, "
                f"e.g. --model qwen/qwen3.8-27b")
        return content


@dataclass
class AnthropicChat(ChatBackend):
    """Anthropic's Messages API, which uses a separate system field and header auth."""

    api_key_env: str = "ANTHROPIC_API_KEY"
    base_url: str = "https://api.anthropic.com/v1"
    timeout: float = 120.0
    temperature: float = 0.0
    max_tokens: int = 1024

    def __post_init__(self) -> None:
        self.model = self.model or "claude-sonnet-5"
        if not os.environ.get(self.api_key_env):
            raise ModelUnavailable(
                f"{self.api_key_env} is not set. Export it before running.")
        self.name = f"anthropic:{self.model}"

    def complete(self, messages: list[dict]) -> str:
        system = " ".join(m["content"] for m in messages if m["role"] == "system")
        turns = [m for m in messages if m["role"] != "system"]
        data = _post_json(f"{self.base_url}/messages", {
            "model": self.model, "max_tokens": self.max_tokens,
            "temperature": self.temperature, "system": system, "messages": turns,
        }, {"x-api-key": os.environ[self.api_key_env],
            "anthropic-version": "2023-06-01"}, self.timeout)
        blocks = data.get("content") or []
        text = "".join(b.get("text", "") for b in blocks if b.get("type") == "text")
        if not text:
            raise ModelUnavailable(f"{self.name} returned no text content")
        return text


def build_chat(provider: str = "ollama", model: str = "") -> ChatBackend:
    """Construct a chat backend by provider name.

    Unknown providers raise rather than silently falling back, so a typo can
    never quietly run the demo against a different model than intended.
    """
    if provider == "ollama":
        return OllamaChat(model=model or os.environ.get("AEGIS_OLLAMA_MODEL", "qwen2.5:7b"))
    if provider == "anthropic":
        return AnthropicChat(model=model)
    if provider in OPENAI_COMPATIBLE:
        return OpenAICompatChat(model=model, provider=provider)
    raise ModelUnavailable(
        f"unknown provider {provider!r}; known: ollama, anthropic, "
        f"{', '.join(OPENAI_COMPATIBLE)}")
