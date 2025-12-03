import json
import re
from typing import Dict, Any

from mediaflow_proxy.extractors.base import BaseExtractor, ExtractorError

class VKExtractor(BaseExtractor):
    mediaflow_endpoint = "mpd_manifest_proxy"

    async def extract(self, url: str, **kwargs):
        embed_url = self._normalize(url)
        ajax_url = self._build_ajax_url(embed_url)

        headers = {
            "User-Agent": UA,
            "Referer": "https://vkvideo.ru/",
            "Origin": "https://vkvideo.ru",
            "Cookie": "remixlang=0",
            "X-Requested-With": "XMLHttpRequest",
        }

        data = self._build_ajax_data(embed_url)

        response = await self._make_request(ajax_url, method="POST", data=data, headers=headers)
        text = response.text.lstrip("<!--")
        json_data = json.loads(text)

        stream = self._extract_stream(json_data)
        if not stream:
            raise ExtractorError("VK: no MPD URL found")

        # stream == MPD URL
        return {
            "destination_url": stream,
            "request_headers": headers,
            "mediaflow_endpoint": self.mediaflow_endpoint,
        }
