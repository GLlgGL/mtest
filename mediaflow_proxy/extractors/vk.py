class VKExtractor(BaseExtractor):
    #mediaflow_endpoint = "proxy_stream"

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
            headers=headers
        )

        text = response.text.lstrip("<!--")

        try:
            json_data = json.loads(text)
        except:
            raise ExtractorError("VK: invalid JSON payload")

        stream = self._extract_stream(json_data)
        if not stream:
            raise ExtractorError("VK: no playable URL found")

        # This URL is the *main* file that supports Range bytes
        return {
            "destination_url": stream,
            "request_headers": headers,
            "mediaflow_endpoint": self.mediaflow_endpoint,
        }

    def _extract_stream(self, json_data):
        payload = next((i for i in json_data.get("payload", []) if isinstance(i, list)), [])
        params = next((i["player"]["params"][0] for i in payload if isinstance(i, dict) and "player" in i), None)
        if not params:
            return None

        # OK.RU direct stream URLs: type=1 is main file
        return params.get("url1080") or params.get("url720") or params.get("url480") or params.get("url360")
