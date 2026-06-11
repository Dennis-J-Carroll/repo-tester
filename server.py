from __future__ import annotations
import json
import re
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator
from repo_tester.cli import run_scan

ALLOWED_ORIGINS = [
    "https://dennisjcarroll.com",
    "https://www.dennisjcarroll.com",
    "http://localhost:5500",
    "http://127.0.0.1:5500",
    "http://localhost:8080",
    "http://localhost:3000",
]

app = FastAPI(title="repo-tester API", version="2.0.1")
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_methods=["POST", "OPTIONS"],
    allow_headers=["Content-Type"],
)


class ScanRequest(BaseModel):
    url: str

    @field_validator("url")
    @classmethod
    def must_be_github(cls, v: str) -> str:
        if not re.match(r"^https://github\.com/[^/]+/[^/\s]+", v):
            raise ValueError("URL must be a github.com repository URL")
        return v.rstrip("/").removesuffix(".git")


@app.post("/scan")
def scan(req: ScanRequest):
    # plain def — FastAPI/Starlette runs this in a thread pool automatically,
    # so blocking git clone + HTTP calls don't starve the event loop
    try:
        report, file_count = run_scan(req.url)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Scan failed: {exc}")

    repo_name = req.url.replace("https://github.com/", "")
    return {
        **json.loads(report.to_json()),
        "repo_name": repo_name,
        "file_count": file_count,
    }


@app.get("/health")
def health():
    return {"status": "ok"}
