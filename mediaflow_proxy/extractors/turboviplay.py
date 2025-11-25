import re
from typing import Dict, Any

from mediaflow_proxy.extractors.base import BaseExtractor, ExtractorError


class TurboVIPlayExtractor(BaseExtractor):

    mediaflow_endpoint = "hls_manifest_proxy"

    PATTERN = re.compile(
        r'(?:urlPlay|data-hash)\s*=\s*[\'"](?P<url>[^\'"]+)',
        re.DOTALL
    )

    async def extract(self, url: str, **kwargs) -> Dict[str, Any]:
        #
        # 1. Fetch embed page
        #
        response = await self._make_request(url)
        body = response.text

        if "File Not Found" in body or "Pending in queue" in body:
            raise ExtractorError("TurboVIPlay: Video not available")

        #
        # 2. Extract media URL exactly like ResolveURL
        #
        m = self.PATTERN.search(body)
        if not m:
            raise ExtractorError("TurboVIPlay: media URL not found")

        media_url = m.group("url")

        #
        # 3. Normalize to absolute URL
        #
        if media_url.startswith("//"):
            final_url = "https:" + media_url
        elif media_url.startswith("/"):
            origin = re.match(r"https?://[^/]+", url).group(0)
            final_url = origin + media_url
        else:
            final_url = media_url

        #
        # 4. Set referer header
        #
        self.base_headers["referer"] = url

        #
        # 5. Output in MediaFlow format
        #
        return {
            "destination_url": final_url,
            "request_headers": self.base_headers,
            "mediaflow_endpoint": self.mediaflow_endpoint,
        }
