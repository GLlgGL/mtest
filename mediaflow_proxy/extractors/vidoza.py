import re
from typing import Dict, Any
from urllib.parse import urlparse

from mediaflow_proxy.extractors.base import BaseExtractor, ExtractorError


class VidozaExtractor(BaseExtractor):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Segment endpoint for IP-locked .mp4
        self.mediaflow_endpoint = "segment_endpoint"

    async def extract(self, url: str) -> Dict[str, Any]:
        parsed = urlparse(url)
        if not parsed.hostname or "vidoza" not in parsed.hostname:
            raise ExtractorError("VIDOZA: Invalid domain")

        # Fetch embed page
        response = await self._make_request(url)
        html = response.text

        # Extract final .mp4 URL
        mp4_match = re.search(r'sources\s*:\s*\[\{file:"([^"]+\.mp4)"', html)
        if not mp4_match:
            raise ExtractorError("VIDOZA: No playable .mp4 URL found")

        mp4_url = mp4_match.group(1)

        parsed_mp4 = urlparse(mp4_url)
        if not parsed_mp4.scheme or parsed_mp4.scheme not in ("http", "https"):
            raise ExtractorError("VIDOZA: Invalid .mp4 URL scheme")

        # Add referer headers for the proxied request
        headers = self.base_headers.copy()
        headers["referer"] = url

        # Return info pointing to MediaFlow segment proxy
        return {
            "destination_url": mp4_url,
            "request_headers": headers,
            "mediaflow_endpoint": self.mediaflow_endpoint,  # /mpd/segment.mp4
        }
