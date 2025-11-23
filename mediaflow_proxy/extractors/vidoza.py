import re
from typing import Dict, Any
from urllib.parse import urljoin, urlparse

from mediaflow_proxy.extractors.base import BaseExtractor, ExtractorError


class VidozaExtractor(BaseExtractor):
    """
    Extractor for Vidoza streams.
    Supports HLS, DASH, and IP-locked .mp4 URLs.
    Always returns a mediaflow_endpoint to allow MediaFlow proxying.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # endpoint for proxying video segments / streams
        self.mediaflow_endpoint = "dash_segment"

    async def extract(self, url: str) -> Dict[str, Any]:
        parsed = urlparse(url)
        if not parsed.hostname or not parsed.hostname.endswith(("vidoza.net", "videzz.net")):
            raise ExtractorError("VIDOZA: Invalid domain")

        # Request the main embed page
        response = await self._make_request(url)
        html = response.text

        # First, try to find an HLS/DASH manifest
        match_hls = re.search(r'(https?://[^"\']+\.m3u8)', html)
        if match_hls:
            master_url = match_hls.group(1)
            endpoint = "hls_manifest_proxy"
        else:
            # Fallback: find MP4 / direct video URL
            match_mp4 = re.search(r'(https?://[^"\']+\.mp4)', html)
            if not match_mp4:
                raise ExtractorError("VIDOZA: No playable stream found")
            master_url = match_mp4.group(1)
            endpoint = self.mediaflow_endpoint  # always proxy MP4 through MediaFlow

        # Fix relative URLs
        if not master_url.startswith("http"):
            master_url = urljoin(url, master_url)

        # Headers required to bypass IP restriction
        headers = self.base_headers.copy()
        headers["referer"] = url
        headers["user-agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"

        return {
            "destination_url": master_url,
            "request_headers": headers,
            "mediaflow_endpoint": endpoint,
        }
