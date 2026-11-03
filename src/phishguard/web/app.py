import logging
from pathlib import Path
from typing import Any, Protocol

from fastapi import FastAPI, Form, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from phishguard.errors import InvalidURLError
from phishguard.models import AnalysisResult
from phishguard.web.presenters import VERDICT_LABELS, defang

logger = logging.getLogger(__name__)

MAX_URL_LENGTH = 2048

_WEB_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = _WEB_DIR / "templates"
STATIC_DIR = _WEB_DIR / "static"

_MSG_EMPTY = "URL을 입력해 주세요."
_MSG_TOO_LONG = "URL이 너무 깁니다."
_MSG_INTERNAL = "분석 중 오류가 발생했습니다."


class SupportsAnalyze(Protocol):
    def analyze(self, raw_url: str) -> AnalysisResult: ...


class _AnalysisFailure(Exception):
    """A failed request, with the status code and Korean message shown to the user."""

    def __init__(self, status_code: int, message: str) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.message = message


def _error(status_code: int, message: str) -> JSONResponse:
    return JSONResponse({"error": message}, status_code=status_code)


def _run_analysis(analyzer: SupportsAnalyze, url: object) -> AnalysisResult:
    """Validate the raw input and analyze it; shared by the JSON API and the HTML form."""
    if not isinstance(url, str) or not url.strip():
        raise _AnalysisFailure(400, _MSG_EMPTY)
    if len(url) > MAX_URL_LENGTH:
        raise _AnalysisFailure(400, _MSG_TOO_LONG)
    try:
        return analyzer.analyze(url)
    except InvalidURLError as exc:
        raise _AnalysisFailure(400, str(exc)) from exc
    except Exception as exc:
        logger.exception("unexpected error while analyzing URL")
        raise _AnalysisFailure(500, _MSG_INTERNAL) from exc


def create_app(analyzer: SupportsAnalyze) -> FastAPI:
    app = FastAPI(title="PhishGuard")
    templates = Jinja2Templates(directory=TEMPLATES_DIR)  # autoescape stays on (.html)
    templates.env.filters["defang"] = defang
    verdict_labels = {verdict.value: label for verdict, label in VERDICT_LABELS.items()}

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    # The only request body FastAPI validates is POST /api/analyze's JSON object, so every
    # validation error (non-object JSON, malformed JSON, missing body) is an "empty URL".
    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
        return _error(400, _MSG_EMPTY)

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    # Sync endpoints: FastAPI runs them in the threadpool, so blocking httpx calls
    # inside the analyzer do not stall the event loop.
    @app.post("/api/analyze")
    def api_analyze(payload: dict[str, Any]) -> JSONResponse:
        try:
            result = _run_analysis(analyzer, payload.get("url"))
        except _AnalysisFailure as failure:
            return _error(failure.status_code, failure.message)
        return JSONResponse(result.to_dict())

    def render_index(request: Request, url_value: str, error: str | None, status_code: int) -> Response:
        return templates.TemplateResponse(
            request,
            "index.html",
            {"url_value": url_value, "error": error},
            status_code=status_code,
        )

    @app.get("/")
    def index(request: Request) -> Response:
        return render_index(request, "", None, 200)

    @app.post("/analyze")
    def analyze_form(request: Request, url: str = Form("")) -> Response:
        try:
            result = _run_analysis(analyzer, url)
        except _AnalysisFailure as failure:
            return render_index(request, url, failure.message, failure.status_code)
        return templates.TemplateResponse(
            request,
            "result.html",
            {"r": result.to_dict(), "labels": verdict_labels},
        )

    return app
