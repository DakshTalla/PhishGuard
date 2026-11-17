import { age } from "@/lib/format";
import type { HostInfo, LexicalInfo, PageInfo } from "@/lib/types";

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="grid grid-cols-[8.5rem_1fr] gap-3 border-b border-line/60 py-2 text-sm last:border-0">
      <dt className="text-muted">{label}</dt>
      <dd className="min-w-0 break-words text-ink-2">{children}</dd>
    </div>
  );
}

function Flag({ ok, children }: { ok: boolean; children: React.ReactNode }) {
  return (
    <span className="inline-flex items-center gap-1.5">
      <span className="text-xs font-bold" style={{ color: ok ? "var(--color-good)" : "var(--color-critical)" }} aria-hidden="true">
        {ok ? "✓" : "✕"}
      </span>
      {children}
    </span>
  );
}

export function UrlFacts({ lex }: { lex: LexicalInfo }) {
  return (
    <dl>
      <Row label="Host">{lex.unicode_host !== lex.host ? `${lex.unicode_host} (${lex.host})` : lex.host}</Row>
      <Row label="Registrable domain">{lex.registrable_domain}</Row>
      <Row label="Subdomain">{lex.subdomain || "none"}</Row>
      <Row label="Lookalike">
        {lex.lookalike ? `${lex.lookalike.kind} of ${lex.lookalike.legit_domain} ("${lex.lookalike.evidence}")` : "none found"}
      </Row>
      <Row label="Brand mentions">{[...lex.brands_in_host, ...lex.brands_in_path].join(", ") || "none"}</Row>
      <Row label="Phishing words">{lex.suspicious_words.join(", ") || "none"}</Row>
      <Row label="Platform">{lex.platform ?? lex.shortener ?? "own domain"}</Row>
    </dl>
  );
}

export function HostFacts({ host }: { host: HostInfo }) {
  if (host.blocked) return <p className="text-sm text-ink-2">Network checks skipped: {host.blocked}</p>;
  const { dns, tls, whois } = host;
  return (
    <dl>
      <Row label="Domain age">
        {whois?.age_days != null
          ? `${age(whois.age_days)} (registered ${whois.created?.slice(0, 10)} via ${whois.source?.toUpperCase()})`
          : `unknown${whois?.error ? ` (${whois.error})` : ""}`}
      </Row>
      <Row label="Registrar">{whois?.registrar ?? "unknown"}</Row>
      <Row label="TLS certificate">
        {tls?.valid ? (
          <Flag ok>Valid, issued by {tls.issuer}, {tls.age_days} days old, {tls.days_left} days left</Flag>
        ) : tls?.https ? (
          <Flag ok={false}>Invalid: {tls.error}</Flag>
        ) : (
          <Flag ok={false}>No HTTPS ({tls?.error ?? "not checked"})</Flag>
        )}
      </Row>
      <Row label="DNS">
        {dns?.resolves
          ? `${dns.a.join(", ") || "IPv6 only"} · ${dns.mx_count} MX · ${dns.ns_count} NS · min TTL ${dns.min_ttl ?? "?"}s`
          : `does not resolve${dns?.error ? ` (${dns.error})` : ""}`}
      </Row>
    </dl>
  );
}

export function PageFacts({ page }: { page: PageInfo }) {
  if (page.form_count == null) {
    return <p className="text-sm text-ink-2">Page not analysed: {page.error ?? "no HTML returned"}</p>;
  }
  return (
    <dl>
      <Row label="Final URL"><span className="font-mono text-xs">{page.final_url}</span></Row>
      <Row label="Redirects">{page.redirects.length ? `${page.redirects.length} hop(s)` : "none"}</Row>
      <Row label="Title">{page.title || "(none)"}</Row>
      <Row label="Password fields">
        <Flag ok={!page.password_fields}>{page.password_fields}</Flag>
      </Row>
      <Row label="Forms">
        {page.form_count} total · {page.external_form_count} post to another site
        {page.mailto_form ? " · one emails its data" : ""}
      </Row>
      <Row label="Brand in title">{page.brands_in_title?.join(", ") || "none"}</Row>
      <Row label="Iframes">{page.iframe_count}</Row>
    </dl>
  );
}
