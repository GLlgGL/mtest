import { Context, Format, Meta, UrlResult } from '../types';
import { Extractor } from './Extractor';
import {
  buildMediaFlowProxyExtractorStreamUrl,
  supportsMediaFlowProxy
} from '../utils';

export class VidGuard extends Extractor {
  public readonly id = 'VidGuard';
  public readonly label = 'VidGuard(MFP)';
  public override readonly ttl = 10800000; // 3h
  public override viaMediaFlowProxy = true;

  private domains = [
    'vidguard.to', 'vid-guard.com', 'vgfplay.com', 'vgfplay.xyz',
    'vgembed.com', 'vembed.net', 'embedv.net', 'v6embed.xyz',
    'go-streamer.net', 'fslinks.org', 'bembed.net', 'listeamed.net',
    'kinoger.pw', 'moflix-stream.day',
    '6tnutl8knw.sbs', 'dhmu4p2hkp.sbs', 'gsfjzmqu.sbs'
  ];

  // domains that must be forced to listeamed.net (same as Python)
  private forceToListeamed = [
    'vidguard', 'vid-guard', 'vgfplay.com', 'vgembed',
    'vembed.net', 'embedv.net', 'go-streamer.net'
  ];

  public supports(ctx: Context, url: URL): boolean {
    return this.domains.some(d => url.host.includes(d)) && supportsMediaFlowProxy(ctx);
  }

  // 🔥 Force all supported hosts to listeamed.net before normalizing
  private forceHost(url: URL): URL {
    const host = url.host;
    if (this.forceToListeamed.some(x => host.includes(x))) {
      return new URL(url.toString().replace(host, "listeamed.net"));
    }
    return url;
  }

  // Convert /v/{id}, /d/{id}, /e/{id} → /e/{id} and force the domain
  public override normalize(url: URL): URL {
    url = this.forceHost(url);

    const parts = url.pathname.split('/').filter(Boolean);
    const first = parts[0];

    if (parts.length >= 2 && first && ['e', 'v', 'd'].includes(first)) {
      const mediaId = parts[1];
      return new URL(`${url.origin}/e/${mediaId}`);
    }

    const slug = parts[parts.length - 1];
    return new URL(`${url.origin}/e/${slug}`);
  }

  // MAIN
  protected async extractInternal(
    ctx: Context,
    url: URL,
    meta: Meta
  ): Promise<UrlResult[]> {

    const referer = meta.referer ?? "https://listeamed.net/";

    const headers: Record<string, string> = {
      referer: referer,
      origin: "https://listeamed.net",
      "user-agent":
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36",
    };

    const proxiedUrl = await buildMediaFlowProxyExtractorStreamUrl(
      ctx,
      this.fetcher,
      this.id,
      url,
      headers
    );

    return [
      {
        url: proxiedUrl,
        format: Format.hls,
        label: this.label,
        sourceId: `${this.id}_${meta.countryCodes?.join('_') ?? 'all'}`,
        ttl: this.ttl,
        requestHeaders: headers,
        meta: { ...meta }
      }
    ];
  }
}
