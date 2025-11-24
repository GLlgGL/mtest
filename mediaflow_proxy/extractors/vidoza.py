import re
from typing import Dict, Any
from urllib.parse import urlparse

from mediaflow_proxy.extractors.base import BaseExtractor, ExtractorError


class VidozaExtractor(BaseExtractor):
    async def extract(self, url: str, **kwargs) -> Dict[str, Any]:
        parsed = urlparse(url)

        if not parsed.hostname or not parsed.hostname.endswith("videzz.net"):
            raise ExtractorError("VIDOZA: Invalid domain")

        # Fetch the embed page with Vidoza referer
        response = await self._make_request(
            url,
            headers={"referer": "https://vidoza.net/"}
        )
        html = response.text

        # Extract the .mp4 URL
        match = re.search(r'https://[^"]+\.mp4', html)
        if not match:
            raise ExtractorError("VIDOZA: Unable to find video URL in embed page")

        mp4_url = match.group(0)

        # Prepare headers
        headers = self.base_headers.copy()
        headers["referer"] = "https://vidoza.net/"

        # IMPORTANT:
        # no mediaflow_endpoint override here → behaves like DoodStream
        return {
            "destination_url": mp4_url,
            "request_headers": headers,
            # BaseExtractor already sets mediaflow_endpoint="stream"
        }