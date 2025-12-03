import json
import re
from typing import Dict, Any

from mediaflow_proxy.extractors.base import BaseExtractor, ExtractorError
import httpx


UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/129.0 Safari/537.36"
)


class VKExtractor(BaseExtractor):
    # always use DASH handler
    mediaflow_endpoint = "mpd_manifest_proxy"

    async def extract(self, url: str, **kwargs) -> Dict[str, Any]:
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

        response = await self._make_request(
            ajax_url,
            method="POST",
            data=data,
            headers=headers,
        )

        text = response.text
        if text.startswith("<!--"):
            text = text[4:]

        try:
            json_data = json.loads(text)
        except:
            raise ExtractorError("VK: invalid JSON payload")

        stream_url = await self._extract_stream(json_data)
        if not stream_url:
            raise ExtractorError("VK: no playable stream URL found")

        return {
            "destination_url": stream_url,
            "request_headers": headers,
            "mediaflow_endpoint": self.mediaflow_endpoint,
        }

    # ---------- HELPERS ----------

    def _normalize(self, url: str) -> str:
        if "video_ext.php" in url:
            return url

        m = re.search(r"video(\d+)_(\d+)", url)
        if m:
            oid, vid = m.groups()
            return f"https://vk.com/video_ext.php?oid={oid}&id={vid}"

        return url

    def _build_ajax_url(self, embed_url: str) -> str:
        host = re.search(r"https?://([^/]+)", embed_url).group(1)
        return f"https://{host}/al_video.php?act=show"

    def _build_ajax_data(self, embed_url: str) -> Dict[str, str]:
        qs = re.search(r"\?(.*)", embed_url)
        params = dict(x.split("=") for x in qs.group(1).split("&")) if qs else {}

        return {
            "act": "show",
            "al": "1",
            "video": f"{params.get('oid')}_{params.get('id')}",
        }

    async def _extract_stream(self, json_data: Any) -> str:
        payload = next(
            (item for item in json_data.get("payload", []) if isinstance(item, list)),
            []
        )

        params = None
        for item in payload:
            if isinstance(item, dict) and item.get("player"):
                params = item["player"]["params"][0]
                break

        if not params:
            return None

        # Possible HLS source
        hls_url = (
            params.get("hls")
            or params.get("hls_ondemand")
            or params.get("hls_live")
        )

        # try HLS first — but validate!
        if hls_url:
            async with httpx.AsyncClient() as client:
                head = await client.get(hls_url, timeout=10)

            # If XML → DASH (MPD)
            if head.text.lstrip().startswith("<MPD"):
                return hls_url

            # real HLS
            return hls_url

        # fallback to MPD/dash
        dash = params.get("dash") or params.get("dash_ondemand")
        if dash:
            return dash

        # fallback MP4 qualities
        return (
            params.get("url1080")
            or params.get("url720")
            or params.get("url480")
            or params.get("url360")
        )
