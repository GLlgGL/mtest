import re
from typing import Dict, Any
from urllib.parse import urlparse

from mediaflow_proxy.extractors.base import BaseExtractor, ExtractorError


class VidozaExtractor(BaseExtractor):
    """
    Extracts FINAL mp4 URL from Vidoza/Videzz embed page.
    Only ONE request is made. The mp4 returned is the REAL direct link.
    This works exactly like DoodStreamExtractor.
    """

    async def extract(self, url: str, **kwargs) -> Dict[str, Any]:

        parsed = urlparse(url)
        if not parsed.hostname or not (
            parsed.hostname.endswith("vidoza.net") or
            parsed.hostname.endswith("videzz.net")
        ):
            raise ExtractorError("VIDOZA: Invalid domain")

        # --- One single request to embed page ---
        response = await self._make_request(
            url,
            headers={"referer": "https://vidoza.net/"}
        )
        html = response.text

        # Extract mp4 URL
        match = re.search(r'https://[^"]+\.mp4', html)
        if not match:
            raise ExtractorError("VIDOZA: Unable to find mp4 URL in page")

        mp4_url = match.group(0)

        # Prepare headers for the REAL mp4
        headers = self.base_headers.copy()
        headers["referer"] = "https://vidoza.net/"
        headers["range"] = "bytes=0-"

        return {
            "destination_url": mp4_url,
            "request_headers": headers,
            "mediaflow_endpoint": self.mediaflow_endpoint,  # Do NOT override
        }