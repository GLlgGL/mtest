import json
import re
from typing import Dict, Any

from mediaflow_proxy.extractors.base import BaseExtractor, ExtractorError

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/129.0 Safari/537.36"
)


class VKExtractor(BaseExtractor):
    # IMPORTANT: VK now uses DASH MPD, not HLS!
    mediaflow_endpoint = "mpd_manifest_proxy"

    async def extract(self, url: str, **kwargs) -> Dict[str, Any]:
        embed_url = self._normalize(url)

        # Step 1 — VK AJAX internal API call
        ajax_url = self._build_ajax_url(embed_url)

        headers = {
            "User-Agent": UA,
            "Referer": "https://vkvideo.ru/",
            "Origin": "https://vkvideo.ru",
            "Cookie": "remixlang=0",
            "X-Requested-With": "XMLHttpRequest",
        }

        data = self._build_ajax_data(embed_url)

        response = await self._make_request(
            ajax_url,
            method="POST",
            data=data,
            headers=headers
        )

        text = response.text
        if text.startswith("<!--"):
            text = text[4:]

        try:
            json_data = json.loads(text)
        except:
            raise ExtractorError("VK: invalid JSON payload")

        stream = self._extract_stream(json_data)
        if not stream:
            raise ExtractorError("VK: no playable HLS/MPD stream found")

        return {
            "destination_url": stream,
            "request_headers": headers,
            "mediaflow_endpoint": self.mediaflow_endpoint,
        }

    # --------------------------------------------------------------
    # HELPERS
    # --------------------------------------------------------------

    def _normalize(self, url: str) -> str:
        """Normalize into /video_ext.php?oid=X&id=Y format."""
        if "video_ext.php" in url:
            return url

        m = re.search(r"video(\-?\d+)_(\d+)", url)
        if not m:
            return url

        oid, vid = m.group(1), m.group(2)
        return f"https://vk.com/video_ext.php?oid={oid}&id={vid}"

    def _build_ajax_url(self, embed_url: str) -> str:
        host = re.search(r"https?://([^/]+)", embed_url).group(1)
        return f"https://{host}/al_video.php?act=show"

    def _build_ajax_data(self, embed_url: str) -> Dict[str, str]:
        qs = re.search(r"\?(.*)", embed_url)
        parts = dict(x.split("=") for x in qs.group(1).split("&")) if qs else {}

        return {
            "act": "show",
            "al": "1",
            "video": f"{parts.get('oid')}_{parts.get('id')}",
        }

    def _extract_stream(self, json_data: Any) -> str:
        """Extract DASH (preferred) or fallback HLS."""
        payload = []
        for item in json_data.get("payload", []):
            if isinstance(item, list):
                payload = item

        params = None
        for item in payload:
            if isinstance(item, dict) and item.get("player"):
                params = item["player"]["params"][0]

        if not params:
            return None

        # Prefer DASH MPD first
        if params.get("dash"):
            return params["dash"]

        # Fallback to HLS links
