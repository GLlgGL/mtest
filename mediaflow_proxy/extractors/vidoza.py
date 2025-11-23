import re
from typing import Dict, Any
from urllib.parse import urlparse, urljoin

from mediaflow_proxy.extractors.base import BaseExtractor, ExtractorError


class VidozaExtractor(BaseExtractor):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # We'll use the HLS proxy endpoint to bypass IP locks
        self.mediaflow_endpoint = "hls_manifest_proxy"

    async def extract(self, url: str, **kwargs) -> Dict[str, Any]:
        parsed = urlparse(url)
        if not parsed.hostname or not any(h in parsed.hostname for h in ("vidoza", "videzz.net")):
            raise ExtractorError("VIDOZA: Invalid domain")

        # --- Fetch embed page ---
        response = await self._make_request(url, follow_redirects=True)
        html = response.text

        # --- Extract video source ---
        # Videzz uses a JS variable "sources" or "file" containing the .mp4 or HLS URL
        match = re.search(r'sources\s*:\s*\[\{file\s*:\s*"([^"]+)"', html)
        if not match:
            match = re.search(r'file\s*:\s*"([^"]+)"', html)

        if not match:
            raise ExtractorError("VIDOZA: Unable to find video URL in embed page")

        video_url = match.group(1)
        if not video_url.startswith("http"):
            video_url = urljoin(url, video_url)

        # --- Return structure for MediaFlow Proxy ---
        headers = self.base_headers.copy()
        headers["referer"] = url

        return {
            "destination_url": video_url,
            "request_headers": headers,
            "mediaflow_endpoint": self.mediaflow_endpoint,
        }
