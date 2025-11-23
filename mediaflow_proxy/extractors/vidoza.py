import re
from urllib.parse import urlparse
from mediaflow_proxy.extractors.base import BaseExtractor, ExtractorError

class VidozaExtractor(BaseExtractor):
    """
    Extractor for Vidoza URLs. Handles both direct MP4 and DASH/MPD streams.
    """

    async def extract(self, url: str) -> dict:
        """
        Extract the playable stream URL from a Vidoza embed page.

        Args:
            url (str): The embed URL.

        Returns:
            dict: {
                "destination_url": str,  # final playable URL
                "mediaflow_endpoint": str | None,  # "mpd_segment" for DASH, None for direct MP4
                "request_headers": dict  # optional headers for the request
            }
        """
        try:
            # Fetch the embed page
            async with self.httpx_client as client:
                resp = await client.get(url)
                resp.raise_for_status()
                html = resp.text

            # Attempt to find a direct MP4 URL
            mp4_match = re.search(r'(https?://[^\'" >]+\.mp4)', html)
            if mp4_match:
                direct_url = mp4_match.group(1)
                return {
                    "destination_url": direct_url,
                    "mediaflow_endpoint": None,  # direct MP4 → no segment proxy needed
                    "request_headers": {}
                }

            # Attempt to find a DASH/MPD manifest URL
            mpd_match = re.search(r'(https?://[^\'" >]+\.mpd)', html)
            if mpd_match:
                mpd_url = mpd_match.group(1)
                return {
                    "destination_url": mpd_url,
                    "mediaflow_endpoint": "mpd_segment",  # proxy segments through mpd route
                    "request_headers": {}
                }

            # If nothing found, raise error
            raise ExtractorError("No playable video URL found on Vidoza page.")

        except Exception as e:
            raise ExtractorError(f"Vidoza extraction failed: {e}")
