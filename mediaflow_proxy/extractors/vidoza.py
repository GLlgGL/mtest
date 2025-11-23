import re
from typing import Dict, Any
from urllib.parse import urlparse

from mediaflow_proxy.extractors.base import BaseExtractor, ExtractorError


class VidozaExtractor(BaseExtractor):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mediaflow_endpoint = "stream"

    async def extract(self, url: str, **kwargs) -> Dict[str, Any]:
        parsed = urlparse(url)

        if not parsed.hostname or (
            not parsed.hostname.endswith("videzz.net")
            and not parsed.hostname.endswith("vidoza.net")
        ):
            raise ExtractorError("VIDOZA: Invalid domain")

        # --- Step 1: Load embed page with browser headers ---
        resp = await self._make_request(
            url,
            headers={
                "referer": "https://vidoza.net/",
                "user-agent": self.base_headers["user-agent"],
                "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            }
        )
        html = resp.text

        # --- Step 2: Extract direct MP4 URL ---
        match = re.search(r'https://[^"]+\.mp4', html)
        if not match:
            raise ExtractorError("VIDOZA: Unable to find video URL in embed")

        mp4_url = match.group(0)

        # --- Step 3: Collect cookies from embed page response ---
        cookies = resp.cookies  # httpx CookieJar

        cookie_header = "; ".join([f"{k}={v}" for k, v in cookies.items()])

        # --- Step 4: build request headers for MP4 request ---
        headers = {
            "referer": "https://vidoza.net/",
            "cookie": cookie_header,
            "user-agent": self.base_headers["user-agent"],
            "accept": "*/*",
            "sec-fetch-mode": "no-cors",
        }

        return {
            "destination_url": mp4_url,
            "request_headers": headers,
            "mediaflow_endpoint": self.mediaflow_endpoint,
        }
