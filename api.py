"""
AI Phishing Scanner - FastAPI REST API wrapper
"""
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
from scanner.url_scanner import URLScanner
from scanner.email_scanner import EmailScanner

app = FastAPI(title="AI Phishing Scanner API", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

class URLScanRequest(BaseModel):
    url: str
    use_llm: bool = True

class EmailScanRequest(BaseModel):
    email_text: str
    use_llm: bool = True

@app.get("/")
def root():
    return {"name": "AI Phishing Scanner API", "version": "1.0.0"}

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/scan/url")
def scan_url(request: URLScanRequest):
    try:
        scanner = URLScanner(use_llm=request.use_llm)
        return scanner.scan(request.url)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/scan/email")
def scan_email(request: EmailScanRequest):
    try:
        scanner = EmailScanner(use_llm=request.use_llm)
        return scanner.scan(request.email_text)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
