import re
import json
from typing import Dict, Any

from mediaflow_proxy.extractors.base import BaseExtractor, ExtractorError


class VKExtractor(BaseExtractor):
    """
    VK video extractor for MediaFlow Proxy.
    Behaves like ResolveURL but uses MediaFlow’s proxy system.
    """

    mediaflow_endpoint = "hls_manifest_proxy"  # same endpoint as FileMoon / StreamWish

    async def extract(self, url: str, **kwargs) -> Dict[str, Any]:
        #
        # 1. Normalize VK embed URL
        #
        embed_url = self._normalize_embed(url)

        #
        # 2. Load embed page
        #
        page = await self._make_request(embed_url)
        html = page.text

        #
        # 3. Try al_video.php AJAX JSON first (ResolveURL logic)
        #
        ajax_url = self._build_ajax_url(embed_url)
        ajax_response = await self._make_request(
            ajax_url,
            method="POST",
            data=self._build_ajax_data(embed_url),
            headers={
                "Referer": embed_url,
                "X-Requested-With": "XMLHttpRequest",
                "Cookie": "remixlang=0",
            }
        )

        json_data = self._safe_parse_json(ajax_response.text)

        stream_url = self._extract_stream_from_ajax(json_data)

        #
        # 4. Fallback: parse <script> var playerParams = {...}
        #
        if not stream_url:
            stream_url = self._extract_from_html(html)

        if not stream_url:
            raise ExtractorError("VK: Unable to extract playable stream")

        #
        # 5. Output to MediaFlow Proxy
        #
        return {
            "destination_url": stream_url,
            "request_headers": {
                "referer": embed_url,
                "origin": "https://vkvideo.ru",
            },
            "mediaflow_endpoint": self.mediaflow_endpoint,
        }

    # ---------------------------------------------------------
    # Helpers identical to ResolveURL → translated to Python
    # ---------------------------------------------------------

    def _normalize_embed(self, url: str) -> str:
        """
        Ensures URL is in the form:
          /video_ext.php?oid=XXX&id=YYY&hash=ZZZ
        """
        if "video_ext.php" in url:
            return url

        match = re.search(r"video(\d+)_(\d+)", url)
        if not match:
            return url

        oid, vid = match.group(1), match.group(2)
        return f"https://vk.com/video_ext.php?oid={oid}&id={vid}"

    def _build_ajax_url(self, embed_url: str) -> str:
        host = re.search(r"https?://([^/]+)", embed_url).group(1)
        return f"https://{host}/al_video.php?act=show"

    def _build_ajax_data(self, embed_url: str) -> Dict[str, str]:
        qs = re.search(r"\?(.*)", embed_url)
        if not qs:
            return {}

        params = dict(x.split("=") for x in qs.group(1).split("&") if "=" in x)

        oid = params.get("oid")
        vid = params.get("id")

        return {
            "act": "show",
            "al": "1",
            "video": f"{oid}_{vid}"
        }

    def _safe_parse_json(self, text: str) -> Any:
        text = text.strip()
        if text.startswith("<!--"):
            text = text[4:]
        try:
            return json.loads(text)
        except:
            return None

    def _extract_stream_from_ajax(self, json_data: Any) -> str:
        if not json_data or "payload" not in json_data:
            return None

        payload = None
        for item in json_data["payload"]:
            if isinstance(item, list):
                payload = item

        if not payload:
            return None

        params = None
        for item in payload:
            if isinstance(item, dict) and "player" in item:
                params = item["player"]["params"][0]

        if not params:
            return None

        # Look for url240, url360, url480, url720, url1080...
        for key, val in params.items():
            if key.startswith("url"):
                return val

        # Fallback
        return params.get("hls") or params.get("hls_live") or params.get("hls_ondemand")

    def _extract_from_html(self, html: str) -> str:
        match = re.search(r"var\s*playerParams\s*=\s*(\{.+?\});", html)
        if not match:
            return None

        try:
            obj = json.loads(match.group(1))
        except:
            return None

        params = obj.get("params", [{}])[0]
        return params.get("hls") or params.get("hls_ondemand")
