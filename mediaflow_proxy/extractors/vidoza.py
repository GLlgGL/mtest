import re
from typing import Dict, Any
from urllib.parse import urlparse

import httpx
from mediaflow_proxy.extractors.base import BaseExtractor, ExtractorError


class VidozaExtractor(BaseExtractor):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mediaflow_endpoint = "stream"

    # --- Override _make_request so cookies + redirects work ---
    async def _fetch(self, url: str, headers: dict):
        async with httpx.AsyncClient(
            headers=headers,
            follow_redirects=True,
            timeout=20,
            trust_env=True,          # allow Cloudflare TLS settings
        ) as client:
            resp = await client.get(url)
            resp.raise_for_status()
            return resp, client.cookies

    async def extract(self, url: str, **kwargs) -> Dict[str, Any]:
        parsed = urlparse(url)

        if not parsed.hostname or (
            not parsed.hostname.endswith("videzz.net")
            and not parsed.hostname.endswith("vidoza.net")
        ):
            raise ExtractorError("VIDOZA: Invalid domain")

        # Browser headers required for Cloudflare
        browser_headers = {
            "referer": "https://vidoza.net/",
            "user-agent": self.base_headers["user-agent"],
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "accept-language": "en-US,en;q=0.9",
            "sec-fetch-mode": "navigate",
        }

        # --- STEP 1: Load embed page, capture cookies ---
        resp, cookies = await self._fetch(url, browser_headers)
        html = resp.text

        # Extract MP4
        match = re.search(r'https://[^"]+\.mp4', html)
        if not match:
            raise ExtractorError("VIDOZA: Unable to find MP4 in embed page")

        mp4_url = match.group(0)

        # Build cookie header
        cookie_header = "; ".join([f"{k}={v}" for k, v in cookies.items()])

        # --- STEP 2: Prepare headers for MP4 request ---
        stream_headers = {
            "referer": "https://vidoza.net/",
            "cookie": cookie_header,
            "user-agent": self.base_headers["user-agent"],
            "accept": "*/*",
            "origin": "https://vidoza.net",
            "sec-fetch-mode": "no-cors",
        }

        return {
            "destination_url": mp4_url,
            "request_headers": stream_headers,
            "mediaflow_endpoint": self.mediaflow_endpoint,
        }
