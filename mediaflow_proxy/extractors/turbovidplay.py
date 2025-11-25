import re
from typing import Dict, Any

from mediaflow_proxy.extractors.base import BaseExtractor, ExtractorError


class TurboVidPlayExtractor(BaseExtractor):
    domains = [
        "turboviplay.com",
        "emturbovid.com",
        "tuborstb.co",
        "javggvideo.xyz",
        "stbturbo.xyz",
        "turbovidhls.com",
    ]

    mediaflow_endpoint = "hls_manifest_proxy"

    async def extract(self, url: str, **kwargs) -> Dict[str, Any]:
        #
        # 1. Load embed
        #
        response = await self._make_request(url)
        html = response.text

        #
        # 2. Extract "urlPlay" or "data-hash"
        #
        m = re.search(r'(?:urlPlay|data-hash)\s*=\s*[\'"]([^\'"]+)', html)
        if not m:
            raise ExtractorError("TurboViPlay: No media URL found")

        media_url = m.group(1)

        # Normalize protocol
        if media_url.startswith("//"):
            media_url = "https:" + media_url
        elif media_url.startswith("/"):
            media_url = response.url.origin + media_url

        #
        # 3. Fetch the intermediate /data/ playlist
        #
        data_resp = await self._make_request(media_url, headers={"Referer": url})
        playlist = data_resp.text

        #
        # 4. Extract REAL master playlist from inside /data/
        #
        # Examples inside:
        # https://g254.turbosplayer.com/file/<uuid>/master.m3u8
        #
        real_m3u8 = None
        m2 = re.search(r'https://[^\'"\s]+/master\.m3u8', playlist)
        if m2:
            real_m3u8 = m2.group(0)

        if not real_m3u8:
            raise ExtractorError("TurboViPlay: Unable to extract real master playlist")

        #
        # 5. Set referer for final request
        #
        self.base_headers["referer"] = url

        #
        # 6. Output final master URL → MediaFlow will clean PNG headers
        #
        return {
            "destination_url": real_m3u8,
            "request_headers": self.base_headers,
            "mediaflow_endpoint": self.mediaflow_endpoint,
        }
