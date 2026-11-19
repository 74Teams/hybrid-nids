import urllib.parse
from typing import Optional
from nids.engine.packet import ParsedHTTPRequest

class HTTPParser:
    """
    Parser bóc tách gói tin HTTP L7 (Tương đương http_inspect của Snort).
    Trích xuất Method, URI, Query, Headers, Body để phục vụ Rule Engine.
    """

    @staticmethod
    def parse_payload(payload: bytes) -> Optional[ParsedHTTPRequest]:
        if not payload:
            return None

        try:
            # Thử decode payload sang string
            text = payload.decode("utf-8", errors="replace")
        except Exception:
            return None

        lines = text.split("\r\n")
        if not lines or len(lines) < 1:
            return None

        first_line = lines[0].strip()
        parts = first_line.split(" ")
        if len(parts) < 2:
            return None

        # Kiểm tra HTTP methods phổ biến
        method = parts[0].upper()
        if method not in {"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"}:
            return None

        raw_uri = parts[1]
        version = parts[2] if len(parts) > 2 else "HTTP/1.1"

        # Tách path và query param
        parsed_url = urllib.parse.urlparse(raw_uri)
        path = parsed_url.path
        query = parsed_url.query

        # Tách Header & Body
        headers = {}
        body = ""
        is_body = False
        body_lines = []

        for line in lines[1:]:
            if is_body:
                body_lines.append(line)
                continue
            if line == "":
                is_body = True
                continue
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()

        if body_lines:
            body = "\r\n".join(body_lines)

        return ParsedHTTPRequest(
            method=method,
            uri=raw_uri,
            path=path,
            query_params=query,
            version=version,
            headers=headers,
            body=body,
        )
