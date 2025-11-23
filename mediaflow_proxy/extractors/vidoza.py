import re
from typing import Dict, Any
from urllib.parse import urlparse

from mediaflow_proxy.extractors.base import BaseExtractor, ExtractorError


class VidozaExtractor(BaseExtractor):
    """
    Minimal Vidoza extractor for direct .mp4 files.
    Always uses the `/stream` endpoint in MediaFlow Proxy.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mediaflow_endpoint = "stream"  # points to /stream route

    async def extract(self, url: str) -> Dict[str, Any]:
        parsed = urlparse(url)
        valid_domains = ("vidoza.net", "vidoza.co", "videzz.net")
        hostname = parsed.hostname.lower() if parsed.hostname else ""

        if not hostname or not (hostname in valid_domains or any(hostname.endswith(f".{d}") for d in valid_domains)):
            raise ExtractorError("Vidoza: Invalid domain")

        # Fetch the page
        response = await self._make_request(url)
        html = response.text

        if not html or "Video not found" in html:
            raise ExtractorError("Vidoza: Video not found")

        # Extract the direct .mp4 URL
        match = re.search(
            r'(?:file|src)\s*[:=]\s*["\'](?P<url>https?://[^"\']+\.mp4)["\']',
            html,
            re.IGNORECASE
        )
        if not match:
            raise ExtractorError("Vidoza: Direct .mp4 URL not found")

        mp4_url = match.group("url")

        # Validate URL
        parsed_mp4 = urlparse(mp4_url)
        if parsed_mp4.scheme not in ("http", "https"):
            raise ExtractorError("Vidoza: Invalid .mp4 URL scheme")

        # Return structure for MediaFlow Proxy
        return {
            "destination_url": mp4_url,
            "request_headers": {"referer": url},  # Vidoza usually requires referer
            "mediaflow_endpoint": self.mediaflow_endpoint,  # use /stream
        }
