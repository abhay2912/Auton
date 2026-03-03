"""
HTTP tools for Auton v2.

Optimized for pentest efficiency:
- http_get returns status code + headers + body
- http_post fixes double-send bug, returns status + headers + body
- http_request for arbitrary methods (PUT, DELETE, PATCH, OPTIONS)
"""

import urllib.request
import urllib.parse
import ssl
import json
from typing import Optional
from auton.tools.registry import registry


def _make_ssl_context():
    """Create an unverified SSL context (for testing self-signed certs)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _format_response(response) -> str:
    """Format an HTTP response into a structured, LLM-friendly string."""
    parts = []
    parts.append(f"Status: {response.status} {response.reason}")
    
    # Headers (selected relevant ones for pentesting)
    relevant_headers = [
        "content-type", "server", "x-powered-by", "set-cookie",
        "location", "x-frame-options", "content-security-policy",
        "access-control-allow-origin", "www-authenticate",
        "x-xss-protection", "strict-transport-security",
    ]
    
    headers = dict(response.headers)
    header_lines = []
    for key, value in headers.items():
        if key.lower() in relevant_headers:
            header_lines.append(f"  {key}: {value}")
    
    if header_lines:
        parts.append("Headers:")
        parts.extend(header_lines)
    
    # Body
    body = response.read().decode('utf-8', errors='replace')
    
    # Truncate very long bodies
    if len(body) > 5000:
        parts.append(f"Body ({len(body)} chars, truncated):")
        parts.append(body[:5000])
        parts.append(f"... [{len(body) - 5000} more chars]")
    else:
        parts.append(f"Body ({len(body)} chars):")
        parts.append(body)
    
    return "\n".join(parts)


@registry.register
def http_get(url: str) -> str:
    """
    Performs an HTTP GET request.
    Returns status code, security-relevant headers, and response body.
    
    Args:
        url: The target URL (must start with http:// or https://).
    """
    print(f"[Tool] http_get: {url}")
    try:
        ctx = _make_ssl_context()
        req = urllib.request.Request(url, method='GET')
        req.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
        
        with urllib.request.urlopen(req, context=ctx, timeout=15) as response:
            return _format_response(response)
    except urllib.error.HTTPError as e:
        # Still return the error response — it contains useful info
        parts = [f"Status: {e.code} {e.reason}"]
        headers = dict(e.headers)
        for key, value in headers.items():
            parts.append(f"  {key}: {value}")
        try:
            body = e.read().decode('utf-8', errors='replace')
            parts.append(f"Body:\n{body[:3000]}")
        except Exception:
            pass
        return "\n".join(parts)
    except Exception as e:
        return f"Error performing GET request: {e}"


@registry.register
def http_post(url: str, data: str, content_type: str = "application/x-www-form-urlencoded") -> str:
    """
    Performs an HTTP POST request.
    Returns status code, headers, and response body.
    
    Args:
        url: The URL to request.
        data: The body data to send.
        content_type: Content-Type header (default: form-urlencoded).
    """
    print(f"[Tool] http_post: {url} (data: {data[:80]})")
    try:
        ctx = _make_ssl_context()
        encoded_data = data.encode('utf-8')
        
        req = urllib.request.Request(url, data=encoded_data, method='POST')
        req.add_header('Content-Type', content_type)
        req.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
        
        # FIX: Pass data only in Request constructor, NOT again in urlopen
        with urllib.request.urlopen(req, context=ctx, timeout=15) as response:
            return _format_response(response)
    except urllib.error.HTTPError as e:
        parts = [f"Status: {e.code} {e.reason}"]
        try:
            body = e.read().decode('utf-8', errors='replace')
            parts.append(f"Body:\n{body[:3000]}")
        except Exception:
            pass
        return "\n".join(parts)
    except Exception as e:
        return f"Error performing POST request: {e}"


@registry.register
def http_request(url: str, method: str = "GET", data: str = "", 
                 headers: str = "{}") -> str:
    """
    Performs an arbitrary HTTP request (GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD).
    Returns status code, headers, and response body.
    
    Args:
        url: The target URL.
        method: HTTP method (GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD).
        data: Request body (for POST/PUT/PATCH).
        headers: JSON string of additional headers.
    """
    print(f"[Tool] http_request: {method} {url}")
    try:
        ctx = _make_ssl_context()
        encoded_data = data.encode('utf-8') if data else None
        
        req = urllib.request.Request(url, data=encoded_data, method=method.upper())
        req.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
        
        # Parse custom headers
        try:
            custom_headers = json.loads(headers) if headers and headers != "{}" else {}
            for key, value in custom_headers.items():
                req.add_header(key, value)
        except json.JSONDecodeError:
            pass
        
        with urllib.request.urlopen(req, context=ctx, timeout=15) as response:
            return _format_response(response)
    except urllib.error.HTTPError as e:
        parts = [f"Status: {e.code} {e.reason}"]
        try:
            body = e.read().decode('utf-8', errors='replace')
            parts.append(f"Body:\n{body[:3000]}")
        except Exception:
            pass
        return "\n".join(parts)
    except Exception as e:
        return f"Error performing {method} request: {e}"
